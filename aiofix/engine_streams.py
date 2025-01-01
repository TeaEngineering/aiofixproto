import asyncio
import inspect
import logging
import time
import uuid
from contextlib import asynccontextmanager, closing
from typing import Any, AsyncGenerator, Callable, Iterable, Optional

from aiofix import msgtype, tags
from aiofix.message import (
    PEEK_SIZE,
    FIXBuilder,
    FIXMessageIn,
    GarbageBufferError,
    peek_length,
)
from aiofix.spec import ClassFIXSpec, FIX44Spec
from aiofix.validator import BaseFIXValidator, BusinessRejectError, RejectError


class LoginError(RuntimeError):
    pass


class BaseApplication:
    def __init__(
        self,
        spec: type[ClassFIXSpec] = FIX44Spec,
        our_comp: str = "SERVER",
        validator: Optional[BaseFIXValidator] = None,
    ):
        if validator is not None:
            self.validator = validator
        else:
            self.validator = spec().build()

        self.our_comp = our_comp
        self.connections: list[StreamFIXConnection] = []

    async def checkLogin(
        self, fix_msg: FIXMessageIn, connection: "StreamFIXConnection"
    ) -> "StreamFIXSession":
        data = self.validator.validate(fix_msg)

        # we'll accept any senderComp so long as it matches the username
        components = self.parse_components(fix_msg, data)
        hb_interval = data["heartbeat_int"]

        # validate the provided username/password (can be async)
        if not await self.check_credentials(data):
            raise LoginError("Incorrect login")

        return StreamFIXSession(
            logger=connection.logger,
            hb_interval=hb_interval,
            version=fix_msg.version,
            validator=self.validator,
            components=components,
        )

    def parse_components(
        self, fix_msg: FIXMessageIn, data: dict[str, Any]
    ) -> Iterable[tuple[int, str]]:
        # validator does not write session tags to data dictionary, re-parse
        senderCompID: Optional[str] = None
        targetCompID: Optional[str] = None
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

        # raise LoginError if component not acceptable
        self.check_components(senderCompID, targetCompID, data)

        # pack in wire order from *our* perspective
        assert targetCompID
        assert senderCompID
        return [(tags.SenderCompID, targetCompID), (tags.TargetCompID, senderCompID)]

    def check_components(
        self, senderCompID: str, targetCompID: str, data: dict[str, Any]
    ) -> None:
        if targetCompID != self.our_comp:
            raise LoginError(
                f"incorrect targetCompID, expected {self.our_comp} recieved {targetCompID}"
            )
        sender = data["username"]
        if senderCompID != sender:
            raise LoginError(
                f"incorrect senderCompID, expected {sender} recieved {senderCompID}"
            )

    async def check_credentials(self, data: dict[str, Any]) -> bool:
        return False

    async def handle_stream_pair(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        fixconnection = StreamFIXConnection(reader, writer, application=self)
        self.connections.append(fixconnection)
        await fixconnection.read_loop()
        self.connections.remove(fixconnection)


class StreamFIXSession:
    def __init__(
        self,
        version: int,
        validator: BaseFIXValidator,
        components: Iterable[tuple[int, str]],
        logger: Optional[logging.Logger] = None,
        hb_interval: int = 5,
        clock: Callable[[], float] = time.time,
    ):
        if logger:
            self.logger = logger
        else:
            sid = "fixsession-" + "-".join(s for i, s in components)
            self.logger = logging.getLogger(sid)
        self.validator = validator
        self.components = [(i, s.encode()) for i, s in components]
        self.version = version
        self.hb_interval = hb_interval
        self.clock = clock

        self.nextOutbound = 1
        self.expectedInbound = 1
        self.heartbeat_task = asyncio.ensure_future(self.await_heartbeat())
        self.writer: "Optional[StreamFIXConnection]" = None
        self.last_outbound = self.clock()
        self.last_inbound = self.clock()
        self.logon_recieved = False
        self.logout_sent = False

    async def handle_incoming(self, fix_msg: FIXMessageIn) -> None:
        data = self.validator.validate(fix_msg)
        self.last_inbound = self.clock()
        c = getattr(self, "on_" + data["msg_type"])
        if inspect.iscoroutinefunction(c):
            await c(fix_msg, data)
        else:
            raise RuntimeError(f"No async handler defined for {data['msg_type']}")

    async def _post_connect(self) -> None:
        self.logger.info(
            f"post_connect (client) reached - hb_interval={self.hb_interval}"
        )
        await self.post_connect()
        await self.send_login()

    async def _post_login(self) -> None:
        self.logger.info(
            f"post_login (server) reached - hb_interval={self.hb_interval}"
        )
        await self.post_login()
        await self.send_login()
        self.logon_recieved = True

    async def post_login(self) -> None:
        pass

    async def post_connect(self) -> None:
        pass

    async def post_disconnect(self) -> None:
        self.logger.info("post_disconnect (server) reached")

    @asynccontextmanager
    async def send_message(
        self, msg_type: str, msgseqnum: Optional[int] = None
    ) -> AsyncGenerator[FIXBuilder, None]:
        delta = 0
        if msgseqnum is None:
            msgseqnum = self.nextOutbound
            delta = 1
        builder = FIXBuilder(
            self.version, self.components, self.clock, msg_type.encode(), msgseqnum
        )
        yield builder
        outmsg = builder.finish()
        self.nextOutbound += delta
        self.last_outbound = self.clock()
        if self.writer:
            await self.writer.send(outmsg)

    async def send_login(self) -> None:
        async with self.send_message(msgtype.Logon) as builder:
            builder.append(tags.HeartBtInt, self.hb_interval)
            builder.append(tags.EncryptMethod, "0")  # no encryption
            self.embellish_logon(builder)

    async def send_business_message_reject(self, bmr: BusinessRejectError) -> None:
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

    async def send_reject(self, rej: RejectError) -> None:
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
            if rej.refTagID:
                builder.append(tags.RefTagID, rej.refTagID)
            if rej.sessionRejectReason:
                builder.append(tags.SessionRejectReason, rej.sessionRejectReason)
            builder.append(tags.Text, str(rej))

    async def await_heartbeat(self) -> None:
        while True:
            # as we sleep for one second, send heartbeat if were within 1 seconds of the hb_interval
            # and allow one second as "some reasonable transmission time"
            hb_interval = max(self.hb_interval - 2, 1)
            await asyncio.sleep(1.0)
            try:
                if self.writer is None:
                    self.logger.info("tx await_heartbeat returning as writer is None")
                    break

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

    def embellish_logon(self, outbound: FIXBuilder) -> None:
        pass

    async def read_loop_closed(self) -> None:
        self.heartbeat_task.cancel()
        await self.post_disconnect()

    async def on_logon_message(self, msg: FIXMessageIn, data: dict[str, Any]) -> None:
        self.logon_recieved = True

    async def on_heartbeat(self, msg: FIXMessageIn, data: dict[str, Any]) -> None:
        if data.get("test_req_id"):
            self.logger.info(f"Recieved heartbeat response to test request {data}")

    async def on_logout_message(self, msg: FIXMessageIn, data: dict[str, Any]) -> None:
        self.logon_recieved = False
        if not self.logout_sent:  # send recripricol Logout
            async with self.send_message(msgtype.Logout):
                pass

    async def on_test_request(self, msg: FIXMessageIn, data: dict[str, Any]) -> None:
        if self.logon_recieved:
            self.logger.info(
                f"Responding to test request with ID {data['test_req_id']}"
            )
            async with self.send_message(msgtype.Heartbeat) as builder:
                builder.append(tags.TestReqID, data["test_req_id"])
        else:
            self.logger.info(
                f"Ignoring test request {data['test_req_id']} as no logon recieved"
            )

    async def on_reject(self, msg: FIXMessageIn, data: dict[str, Any]) -> None:
        self.logger.info(f"Recieved message Reject: {data}")

    async def on_resend_request(self, msg: FIXMessageIn, data: dict[str, Any]) -> None:
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

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        application: Optional[BaseApplication] = None,
        session: Optional[StreamFIXSession] = None,
    ):
        StreamFIXConnection.counter += 1
        addr = writer.get_extra_info("peername")
        self.connection_id = f"fix-{self.counter}-{addr[0]}:{addr[1]}"
        self.logger = logging.getLogger(self.connection_id)
        self.writer = writer
        self.reader = reader
        self.application = application
        self.timeout_task = asyncio.ensure_future(self.await_logon_timeout())
        self.session = session
        if session:
            session.writer = self
            session.logger = self.logger

    async def read_loop(self) -> None:
        self.logger.debug("Socket (early) connected")
        if self.session:
            await self.session._post_connect()

        self.logger.info("Socket connected")

        # context manager to close() writer if we die with exception
        with closing(self.writer):
            while True:
                try:
                    data = await self.reader.readexactly(PEEK_SIZE)
                    sz = peek_length(data)
                    data = data + await self.reader.readexactly(sz - PEEK_SIZE)
                    fix_msg = FIXMessageIn(data)
                    self.logger.debug(f"Received {fix_msg.buffer!r}")
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
        if self.session:
            await self.session.read_loop_closed()

    async def await_logon_timeout(self) -> None:
        try:
            await asyncio.sleep(15)
            if not self.session and self.writer:
                self.logger.info("Reaping connection with no Logon")
                self.writer.close()
            # we've handed over to the session timers
        except Exception:
            self.logger.exception("timeout aborting")

    async def handle_incoming(self, fix_msg: FIXMessageIn) -> None:
        if self.session:
            await self.session.handle_incoming(fix_msg)
        else:
            # Not yet authenticated, accept exactly one Login message
            if fix_msg.msg_type == msgtype.Logon:
                assert self.application
                self.session = await self.application.checkLogin(fix_msg, self)
                self.session.writer = self
                # Now check sequencing
                # await self.session.handle_incoming(fix_msg)
                await self.session._post_login()
            else:
                raise LoginError("First message not Logon", fix_msg)

    async def send(self, outmsg: FIXMessageIn) -> None:
        if not self.writer.is_closing():
            self.logger.debug(f"sending {outmsg.buffer!r}")
            self.writer.write(outmsg.buffer)

    def time(self) -> float:
        return time.time()

    async def post_connect(self) -> None:
        pass
