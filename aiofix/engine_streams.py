import asyncio
import time
import collections
import uuid
import inspect
import logging
from contextlib import closing

from aiofix.message import PEEK_SIZE, peek_length, FIXMessageIn, GarbageBufferError, FIXBuilder
from aiofix.spec import FIX44Spec
from aiofix import msgtype, tags
from aiofix.validator import BusinessRejectError, RejectError
from asyncio_extras.contextmanager import async_contextmanager


class LoginError(RuntimeError):
    pass


class BaseApplication():
    def __init__(self, spec=FIX44Spec, our_comp='SERVER'):
        self.spec = spec
        self.our_comp = our_comp

    async def checkLogin(self, fix_msg, connection):
        my_validator = self.spec().build()
        data = my_validator.validate(fix_msg)

        # we'll accept any senderComp so long as it matches the username
        components = self.check_components(fix_msg, target=self.our_comp, sender=data['username'])
        hb_interval = data['heartbeat_int']

        kwargs = {'logger': connection.logger, 'hb_interval': hb_interval, 'version': fix_msg.version,
                  'validator': my_validator, 'components': components}

        # Now validate the provided username/password
        return await self.check_credentials_create_session(data, kwargs)

    def check_components(self, fix_msg, target=None, sender=None):
        senderCompID = None
        targetCompID = None
        for field in fix_msg.session_tags():
            if field.tag == 49:
                if senderCompID:
                    raise LoginError('duplicate senderCompID')
                senderCompID = field.value()
            elif field.tag == 56:
                if targetCompID:
                    raise LoginError('duplicate targetCompID')
                targetCompID = field.value()
        if not senderCompID:
            raise LoginError('missing senderCompID on Logon')
        if not targetCompID:
            raise LoginError('missing targetCompID on Logon')
        if targetCompID != target:
            raise LoginError('incorrect targetCompID, expected {} recieved {}'.format(target, targetCompID))
        if senderCompID != sender:
            raise LoginError('incorrect senderCompID, expected {} recieved {}'.format(sender, senderCompID))

        # now pack in wire order from *our* perspective
        return [(49, targetCompID), (56, senderCompID)]

    async def check_credentials_create_session(self, data, kwargs):
        raise LoginError('Incorrect login')


class StreamFIXSession():
    def __init__(self, version=0, validator=None, components=None, logger=None, hb_interval=5, clock=time.time):
        self.logger = logger
        self.validator = validator
        self.nextOutbound = 1
        self.expectedInbound = 1
        self.components = components
        self.version = version
        self.heartbeat_task = asyncio.ensure_future(self.await_heartbeat())
        self.hb_interval = hb_interval
        self.clock = clock
        self.writer = None
        self.last_outbound = self.clock()
        self.last_inbound = self.clock()
        self.logon_recieved = False
        self.logout_sent = False

    async def handle_incoming(self, fix_msg):
        data = self.validator.validate(fix_msg)
        self.last_inbound = self.clock()
        c = getattr(self, 'on_'+data['msg_type'])
        if inspect.iscoroutinefunction(c):
            await c(fix_msg, data)
        else:
            raise RuntimeError('No async handler defined for {}'.format(data['msg_type']))

    async def _post_connect(self):
        self.logger.info('post_connect (client) reached - hb_interval={}'.format(self.hb_interval))
        await self.post_connect()
        await self.send_login()

    async def _post_login(self):
        self.logger.info('post_login (server) reached - hb_interval={}'.format(self.hb_interval))
        await self.post_login()
        await self.send_login()
        self.logon_recieved = True

    async def post_login(self):
        pass

    async def post_connect(self):
        pass

    async def post_disconnect(self):
        self.logger.info('post_disconnect (server) reached')

    @async_contextmanager
    async def send_message(self, msg_type, msgseqnum=None):
        if msgseqnum is None:
            msgseqnum = self.nextOutbound
            self.nextOutbound += 1
        builder = FIXBuilder(self.version, self.components, self.clock, msg_type, msgseqnum)
        yield builder
        outmsg = builder.finish()
        self.last_outbound = self.clock()
        await self.writer.send(outmsg)

    async def send_login(self):
        async with self.send_message('A') as builder:
            builder.append(108, self.hb_interval)
            builder.append(98, '0')  # no encryption
            self.embellish_logon(builder)

    async def send_business_message_reject(self, bmr):
        rejectedMsg = bmr.fixMsg
        # 45 RefSeqNum @RefSeqNum MsgSeqNum of rejected message
        # 372 RefMsgType @RefMsgType The MsgType of the FIX message being referenced.
        # 1130  RefApplVerID @RefApplVerID
        # 379 BusinessRejectRefID @BizRejRefID
        #          The value of the business-level "ID" field on the message being
        #          referenced. Required unless the corresponding ID field (see list
        #          above) was not specified.
        # 380 BusinessRejectReason @BizRejRsn Code to identify reason for a Business
        #       Message Reject message.
        #   0   =   Other
        #   1   =   Unknown ID
        #   2   =   Unknown Security
        #   3   =   Unsupported Message Type
        #   4   =   Application not available
        #   5   =   Conditionally required field missing
        #   6   =   Not Authorized
        #   7   =   DeliverTo firm not available at this time
        #   18  =   Invalid price increment
        # 58  Text
        async with self.send_message('j') as builder:
            builder.append(45, rejectedMsg.seqnum)
            builder.append(372, rejectedMsg.msg_type)
            builder.append(379, bmr.reject_ref_id)
            builder.append(380, bmr.reject_reason)
            builder.append(58,  str(bmr))

    async def await_heartbeat(self):
        while True:
            await asyncio.sleep(1.0)
            try:

                if self.clock() - self.last_outbound >= self.hb_interval and self.logon_recieved:
                    self.logger.debug('Sending heartbeat')
                    async with self.send_message('0') as builder:
                        pass

                in_late = self.clock() - self.last_inbound
                if in_late > 4*self.hb_interval:
                    self.logger.info('Inbound heartbeat is well overdue, closing connection')
                    self.writer.writer.close()
                    break
                elif in_late > 2*self.hb_interval:
                    tr = uuid.uuid4().hex[0:10]
                    self.logger.info('Inbound heartbeat is overdue, sending test request {}'.format(tr))
                    async with self.send_message('1') as builder:
                        builder.append(112, tr)  # TestReqID

            except Exception:
                self.logger.exception('tx heartbeat aborted')

    def embellish_logon(self, outbound):
        pass

    async def read_loop_closed(self):
        self.heartbeat_task.cancel()
        await self.post_disconnect()

    async def on_logon_message(self, msg, data):
        self.logon_recieved = True

    async def on_heartbeat(self, msg, data):
        if data.get('test_req_id'):
            self.logger.info('Recieved heartbeat response to test request {}'.format(data))

    async def on_logout_message(self, msg, data):
        self.logon_recieved = False
        if not self.logout_sent:  # send recripricol Logout
            async with self.send_message('5'):
                pass

    async def on_test_request(self, msg, data):
        if self.logon_recieved:
            self.logger.info('Responding to test request with ID {}'.format(data['test_req_id']))
            async with self.send_message('0') as builder:
                builder.append(112, data['test_req_id'])
        else:
            self.logger.info('Ignoring test request {} as no logon recieved'.format(data['test_req_id']))

    async def on_reject(self, msg, data):
        self.logger.info("Recieved message Reject: {}".format(data))

    async def on_resend_request(self, msg, data):
        self.logger.info("Recieved ResendRequest {}, out nextOutbound is {}".format(data, self.nextOutbound))
        if self.logon_recieved and not self.logout_sent:
            if data['begin_seq_no'] < self.nextOutbound:
                async with self.send_message(msgtype.SequenceReset, msgseqnum=data['begin_seq_no']) as builder:
                    #end_seq_no might be zero to indicate unbounaded replay
                    end = data['end_seq_no'] if data['end_seq_no'] > 0 else self.nextOutbound
                    builder.append(tags.EndSeqNo, end)
                    builder.append(tags.GapFillFlag, 'Y')
            else:
                self.logger.warn('ResendReuqest begin seq no {} exceeds our nextOutbound {} or more than endseqno'
                                 .format(data, self.nextOutbound))


class StreamFIXConnection():
    "Set either application or session"
    counter = 0

    def __init__(self, reader, writer, monitor, application=None, session=None):
        StreamFIXConnection.counter += 1
        addr = writer.get_extra_info('peername')
        self.connection_id = 'fix-{}-{}:{}'.format(self.counter, addr[0], addr[1])
        self.logger = logging.getLogger(self.connection_id)
        self.writer = writer
        self.reader = reader
        self.application = application
        self.timeout_task = asyncio.ensure_future(self.await_logon_timeout())
        self.session = session
        self.monitor = monitor
        if session:
            session.writer = self
            session.logger = self.logger

    async def read_loop(self):
        self.logger.debug('Socket (early) connected')
        if self.session:
            await self.session._post_connect()
        # await self.monitor[self.connection_id] = self
        await self.monitor.__setitem__(self.connection_id, self)
        self.monitor.addHandlers(self.connection_id, self.logger)
        self.logger.info('Socket connected')

        # context manager to close() writer if we die with exception
        with closing(self.writer):
            while True:
                try:
                    data = await self.reader.readexactly(PEEK_SIZE)
                    sz = peek_length(data)
                    data = data + await self.reader.readexactly(sz - PEEK_SIZE)
                    fix_msg = FIXMessageIn(data)
                    self.logger.debug("Received {}".format(fix_msg.buffer))
                    await self.handle_incoming(fix_msg)
                # Sanitise certain error messages to the websocket logger, dropping the exception
                except (asyncio.streams.IncompleteReadError, ConnectionResetError):
                    self.logger.info('End of stream - incomplete message')
                    break
                except TimeoutError as timeout:
                    self.logger.info('End of stream: {}'.format(timeout))
                    break
                except GarbageBufferError:
                    self.logger.info('Connection aborted - garbage input')
                    break
                except LoginError as le:
                    self.logger.info('Connection aborted as Logon credentials incorrect: {}'.format(le))
                    break
                except RejectError as rej:
                    self.logger.warn('Message rejected: {}'.format(rej))
                    # if session not yet established, tear down after one reject (e.g. badly formed Logon)
                    if not self.session:
                        break
                except BusinessRejectError as bmr:
                    # catch, but stay connected
                    self.logger.warn('Message business rejected: {}'.format(bmr))
                    if self.session:
                        await self.session.send_business_message_reject(bmr)
                except Exception:
                    self.logger.exception('Connection abort due to internal error (contact support for details)')
                    break
        self.writer = None
        await self.monitor.__delitem__(self.connection_id)
        if self.session:
            await self.session.read_loop_closed()

    async def await_logon_timeout(self):
        try:
            await asyncio.sleep(15)
            if not self.session and self.writer:
                self.logger.info('Reaping connection with no Logon')
                self.writer.close()
            # we've handed over to the session timers
        except Exception:
            self.logger.exception('timeout aborting')

    async def handle_incoming(self, fix_msg):
        if self.session:
            await self.session.handle_incoming(fix_msg)
        else:
            # Not yet authenticated, accept exactly one Login message
            if fix_msg.msg_type == 'A':
                self.session = await self.application.checkLogin(fix_msg, self)
                self.session.writer = self
                # Now check sequencing
                # await self.session.handle_incoming(fix_msg)
                await self.session._post_login()
                # trigger update to show logged in status
                await self.monitor.changed(self.connection_id, self)
            else:
                raise LoginError("First message not Logon", fix_msg)

    async def send(self, outmsg):
        if self.writer:
            self.logger.debug("sending {}".format(outmsg.buffer))
            self.writer.write(outmsg.buffer)

    def time(self):
        return time.time()

    async def post_connect(self):
        pass


class BaseMonitor(collections.abc.MutableMapping):

    def __init__(self, *args, **kwargs):
        self.store = dict()
        self.update(dict(*args, **kwargs))  # use the free update to set keys

    def __getitem__(self, key):
        return self.store[key]

    async def __setitem__(self, key, value):
        self.store[key] = value

    async def __delitem__(self, key):
        del self.store[key]

    def __iter__(self):
        return iter(self.store)

    def __len__(self):
        return len(self.store)

    def addHandlers(self, key, logger):
        pass

    async def changed(self, key, value):
        await self.__setitem__(key, value)
