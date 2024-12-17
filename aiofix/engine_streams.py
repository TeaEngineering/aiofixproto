import asyncio
import time
import collections
import uuid
import inspect
import logging
from contextlib import closing

from aiofix.message import (
    PEEK_SIZE,
    peek_length,
    FIXMessageIn,
    GarbageBufferError,
    FIXBuilder,
)
from aiofix.spec import FIX44Spec
from aiofix import msgtype, tags
from aiofix.validator import BusinessRejectError, RejectError
from contextlib import asynccontextmanager


class LoginError(RuntimeError):
    pass


# StreamFIXSession subclasses throw this to send a BusinessMessageReject
class BusinessMessageReject(RuntimeError):
    def __init__(self, message, ref_id="N/A", reject_reason=0):
        super().__init__(message)
        self.reject_ref_id = ref_id
        self.reject_reason = reject_reason


class BaseApplication:
    def __init__(self, spec=FIX44Spec, our_comp="SERVER"):
        self.spec = spec
        self.our_comp = our_comp
        self.monitor = None

    async def checkLogin(self, fix_msg, connection):
        my_validator = self.spec().build()
        data = my_validator.validate(fix_msg)

        # we'll accept any senderComp so long as it matches the username
        components = self.check_components(
            fix_msg, target=self.our_comp, sender=data["username"]
        )
        hb_interval = data["heartbeat_int"]

        kwargs = {
            "logger": connection.logger,
            "hb_interval": hb_interval,
            "version": fix_msg.version,
            "validator": my_validator,
            "components": components,
        }

        # Now validate the provided username/password
        return await self.check_credentials_create_session(data, kwargs)

    def check_components(self, fix_msg, target=None, sender=None):
        senderCompID = None
        targetCompID = None
        for field in fix_msg.session_tags():
            if field.tag == tags.SenderCompID:
                if senderCompID:
                    raise LoginError("duplicate senderCompID")
                senderCompID = field.value()
            elif field.tag == tags.TargetCompID:
                if targetCompID:
                    raise LoginError("duplicate targetCompID")
                targetCompID = field.value()
        if not senderCompID:
            raise LoginError("missing senderCompID on Logon")
        if not targetCompID:
            raise LoginError("missing targetCompID on Logon")
        if targetCompID != target:
            raise LoginError(
                f"incorrect targetCompID, expected {target} recieved {targetCompID}"
            )
        if senderCompID != sender:
            raise LoginError(
                f"incorrect senderCompID, expected {sender} recieved {senderCompID}"
            )

        # now pack in wire order from *our* perspective
        return [(tags.SenderCompID, targetCompID), (tags.TargetCompID, senderCompID)]

    async def check_credentials_create_session(self, data, kwargs):
        raise LoginError("Incorrect login")

    async def handle_stream_pair(self, reader, writer):
        fixconnection = StreamFIXConnection(
            reader, writer, self.monitor, application=self
        )
        await fixconnection.read_loop()


class StreamFIXSession:
    def __init__(
        self,
        version=0,
        validator=None,
        components=None,
        logger=None,
        hb_interval=5,
        clock=time.time,
    ):
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
        c = getattr(self, "on_" + data["msg_type"])
        if inspect.iscoroutinefunction(c):
            try:
                await c(fix_msg, data)
            except BusinessMessageReject as bmr:
                # translate to aiofix.validator.BusinessRejectError, adding current fix_msg as context
                raise BusinessRejectError(
                    bmr.message,
                    fix_msg,
                    ref_id=bmr.ref_id,
                    reject_reason=bmr.reject_reason,
                )
        else:
            raise RuntimeError(f"No async handler defined for {data["msg_type"]}")

    async def _post_connect(self):
        self.logger.info(
            f"post_connect (client) reached - hb_interval={self.hb_interval}"
        )
        await self.post_connect()
        await self.send_login()

    async def _post_login(self):
        self.logger.info(
            f"post_login (server) reached - hb_interval={self.hb_interval}"
        )
        await self.post_login()
        await self.send_login()
        self.logon_recieved = True

    async def post_login(self):
        pass

    async def post_connect(self):
        pass

    async def post_disconnect(self):
        self.logger.info("post_disconnect (server) reached")

    @asynccontextmanager
    async def send_message(self, msg_type, msgseqnum=None):
        delta = 0
        if msgseqnum is None:
            msgseqnum = self.nextOutbound
            delta = 1
        builder = FIXBuilder(
            self.version, self.components, self.clock, msg_type, msgseqnum
        )
        yield builder
        outmsg = builder.finish()
        self.nextOutbound += delta
        self.last_outbound = self.clock()
        await self.writer.send(outmsg)

    async def send_login(self):
        async with self.send_message(msgtype.Logon) as builder:
            builder.append(tags.HeartBtInt, self.hb_interval)
            builder.append(tags.EncryptMethod, "0")  # no encryption
            self.embellish_logon(builder)

    async def send_business_message_reject(self, bmr):
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
        async with self.send_message(msgtype.BusinessMessageReject) as builder:
            builder.append(tags.RefSeqNum, bmr.fixMsg.seqnum)
            builder.append(tags.RefMsgType, bmr.fixMsg.msg_type)
            builder.append(tags.BusinessRejectRefID, bmr.reject_ref_id)
            builder.append(tags.BusinessRejectReason, bmr.reject_reason)
            builder.append(tags.Text, str(bmr))

    async def send_reject(self, rej):
        # 45 RefSeqNum @RefSeqNum MsgSeqNum of rejected message
        # 372 RefMsgType @RefMsgType The MsgType of the FIX message being referenced.
        # 371 RefTagID @RefTagID The tag number of the FIX field being referenced.
        # 373 SessionRejectReason Code to identify reason for a session-level Reject message.
        #     0 = Invalid Tag Number
        #     1 = Required Tag Missing
        #     2 = Tag not defined for this message type
        #     3 = Undefined tag
        #     4 = Tag specified without a value
        #     5 = Value is incorrect (out of range) for this tag
        #     6 = Incorrect data format for value
        #     7 = Decryption problem
        #     8 = Signature problem
        #     9 = CompID problem
        #    10 = SendingTime Accuracy Problem
        #    11 = Invalid MsgType
        #    12 = XML Validation Error
        #    13 = Tag appears more than once
        #    14 = Tag specified out of required order
        #    15 = Repeating group fields out of order
        #    16 = Incorrect NumInGroup count for repeating group
        #    17 = Non "Data" value includes field delimiter (<SOH> character)
        #    18 = Invalid/Unsupported Application Version
        #    99 = Other
        # 58  Text
        async with self.send_message(msgtype.Reject) as builder:
            builder.append(tags.RefSeqNum, rej.fixMsg.seqnum)
            builder.append(tags.RefMsgType, rej.fixMsg.msg_type)
            if rej.tagID:
                builder.append(tags.RefTagID, rej.tagID)
            if rej.sessionRejectReason:
                builder.append(tags.SessionRejectReason, rej.sessionRejectReason)
            builder.append(tags.Text, str(rej))

    async def await_heartbeat(self):
        while True:
            # as we sleep for one second, send heartbeat if were within 1 seconds of the hb_interval
            # and allow one second as "some reasonable transmission time"
            hb_interval = max(self.hb_interval - 2, 1)
            await asyncio.sleep(1.0)
            try:
                if (
                    self.clock() - self.last_outbound > hb_interval
                    and self.logon_recieved
                ):
                    self.logger.debug("Sending heartbeat")
                    async with self.send_message("0") as builder:
                        pass

                in_late = self.clock() - self.last_inbound
                if in_late > 4 * self.hb_interval:
                    self.logger.info(
                        "Inbound heartbeat is well overdue, closing connection"
                    )
                    self.writer.writer.close()
                    break
                elif in_late > 2 * self.hb_interval:
                    tr = uuid.uuid4().hex[0:10]
                    self.logger.info(
                        f"Inbound heartbeat is overdue, sending test request {tr}"
                    )
                    async with self.send_message("1") as builder:
                        builder.append(tags.TestReqID, tr)  # TestReqID

            except Exception:
                self.logger.exception("tx heartbeat aborted")

    def embellish_logon(self, outbound):
        pass

    async def read_loop_closed(self):
        self.heartbeat_task.cancel()
        await self.post_disconnect()

    async def on_logon_message(self, msg, data):
        self.logon_recieved = True

    async def on_heartbeat(self, msg, data):
        if data.get("test_req_id"):
            self.logger.info(f"Recieved heartbeat response to test request {data}")

    async def on_logout_message(self, msg, data):
        self.logon_recieved = False
        if not self.logout_sent:  # send recripricol Logout
            async with self.send_message(msgtype.Logout):
                pass

    async def on_test_request(self, msg, data):
        if self.logon_recieved:
            self.logger.info(
                f"Responding to test request with ID {data["test_req_id"]}"
            )
            async with self.send_message(msgtype.Heartbeat) as builder:
                builder.append(tags.TestReqID, data["test_req_id"])
        else:
            self.logger.info(
                f"Ignoring test request {data["test_req_id"]} as no logon recieved"
            )

    async def on_reject(self, msg, data):
        self.logger.info(f"Recieved message Reject: {data}")

    async def on_resend_request(self, msg, data):
        self.logger.info(
            f"Recieved ResendRequest {data}, out nextOutbound is {self.nextOutbound}"
        )
        if self.logon_recieved and not self.logout_sent:
            if data["begin_seq_no"] < self.nextOutbound:
                async with self.send_message(
                    msgtype.SequenceReset, msgseqnum=data["begin_seq_no"]
                ) as builder:
                    # Caution: end_seq_no might be zero to indicate unbounaded replay
                    end = self.nextOutbound
                    if data["end_seq_no"] > 0:
                        end = data["end_seq_no"]
                    builder.append(tags.NewSeqNo, end)
                    builder.append(tags.GapFillFlag, "Y")
            else:
                self.logger.warn(
                    f"ResendRequest begin seq no {data} exceeds our nextOutbound {self.nextOutbound} or more than endseqno"
                )


class StreamFIXConnection:
    "Set either application or session"

    counter = 0

    def __init__(self, reader, writer, monitor, application=None, session=None):
        StreamFIXConnection.counter += 1
        addr = writer.get_extra_info("peername")
        self.connection_id = f"fix-{self.counter}-{addr[0]}:{addr[1]}"
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
        self.logger.debug("Socket (early) connected")
        if self.session:
            await self.session._post_connect()
        # await self.monitor[self.connection_id] = self
        await self.monitor.__setitem__(self.connection_id, self)
        self.monitor.addHandlers(self.connection_id, self.logger)
        self.logger.info("Socket connected")

        # context manager to close() writer if we die with exception
        with closing(self.writer):
            while True:
                try:
                    data = await self.reader.readexactly(PEEK_SIZE)
                    sz = peek_length(data)
                    data = data + await self.reader.readexactly(sz - PEEK_SIZE)
                    fix_msg = FIXMessageIn(data)
                    self.logger.debug(f"Received {fix_msg.buffer}")
                    await self.handle_incoming(fix_msg)

                # Sanitise certain error messages to the websocket logger, dropping the exception
                except (asyncio.IncompleteReadError, ConnectionResetError):
                    self.logger.info("End of stream - incomplete message")
                    break
                except TimeoutError as timeout:
                    self.logger.info(f"End of stream: {timeout}")
                    break
                except GarbageBufferError:
                    self.logger.info("Connection aborted - garbage input")
                    break
                except LoginError as le:
                    self.logger.info(
                        f"Connection aborted as Logon credentials incorrect: {le}"
                    )
                    break
                except RejectError as rej:
                    self.logger.warn(f"Message rejected: {rej}")
                    # if session not yet established, tear down after one reject (e.g. badly formed Logon)
                    if self.session:
                        await self.session.send_reject(rej)
                    else:
                        break
                except BusinessRejectError as bmr:
                    # catch, but stay connected
                    self.logger.warn(f"Message business rejected: {bmr}")
                    if self.session:
                        await self.session.send_business_message_reject(bmr)
                except Exception:
                    self.logger.exception(
                        "Connection abort due to internal error (contact support for details)"
                    )
                    break
        self.writer = None
        await self.monitor.__delitem__(self.connection_id)
        if self.session:
            await self.session.read_loop_closed()

    async def await_logon_timeout(self):
        try:
            await asyncio.sleep(15)
            if not self.session and self.writer:
                self.logger.info("Reaping connection with no Logon")
                self.writer.close()
            # we've handed over to the session timers
        except Exception:
            self.logger.exception("timeout aborting")

    async def handle_incoming(self, fix_msg):
        if self.session:
            await self.session.handle_incoming(fix_msg)
        else:
            # Not yet authenticated, accept exactly one Login message
            if fix_msg.msg_type == msgtype.Logon:
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
            self.logger.debug(f"sending {outmsg.buffer}")
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
