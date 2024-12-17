"""
FIXMessage module contains the base FIXMessageIn parser and FIXBuilder
classes, plus a few methods to build instances in test cases (from_delim)
 and assist in protocol parsing (peek_length).

A FIXMessageIn is built from a byte array and verifies the msglength,
checksum and FIX header during construction. It scans for raw data fields
and builds a list of tag numbers and the byte offsets of their values.
Certain mandatory session fields are parsed to allow inspection in higher
level of sequence numbers, msgtype and resend parameters.

If the constructor does not raise an Error, then the message is at least
structually correct, complete and may be cleanly iterated over.
"""

import logging
import time


def from_delim(text, delim="|"):
    buffer = "".join(["\001" if b == delim else b for b in text])
    b = bytes(buffer, "ASCII")
    return FIXMessageIn(b)


class FIXValue:
    def __init__(self, buffer):
        self.tag = 0
        self.buffer = buffer

    def position(self, tag, start, end):
        self.tag = tag
        self.start = start
        self.end = end
        return self

    def value(self):
        return self.buffer[self.start : self.end].decode("cp1252")

    def bytes(self):
        return self.buffer[self.start : self.end]


fixversion_decode = {b"8=FIX.4.2": 42, b"8=FIX.4.4": 44, b"8=FIX.T": 50}
fixversion_encode = dict([(v, k) for (k, v) in fixversion_decode.items()])

# map data-length to data-tag: 95=rawDataLength 96=rawData
data_length_to_tag = {95: 96}
data_tag_to_length = dict([(v, k) for (k, v) in data_length_to_tag.items()])

session_tags = [8, 9, 35, 49, 56, 34, 52, 10]
# beginstring, msglen, msgtype, sender, target, seqnum, sendingtime, checksum

PEEK_SIZE = 30


class GarbageBufferError(RuntimeError):
    pass


def peek_length(buffer):
    """Peek into a (possibly) partial buffer and determine the number of bytes
    needed for the whole message"""
    if type(buffer) is not bytes:
        raise TypeError("wrong type")

    # simple delimit by SOH in first 30 characters
    prefix_parts = buffer[0:PEEK_SIZE].split(b"\001")
    if len(buffer) < PEEK_SIZE:
        return -1  # Need more bytes
    if len(prefix_parts) < 3:
        # Need at least SOH after message length to be valid
        raise GarbageBufferError("Invalid: No tag delimiters (SOH) in message")
    if not buffer[0:2] == b"8=":
        raise ValueError("BeginString[8] must be the 1st field")
    if not prefix_parts[1][0:2] == b"9=":
        raise ValueError("Bodylength[9] must be 2nd field {}".format(buffer))
    body_length = int(prefix_parts[1][2:])

    # validate length: msgtype tag to checksum 10=
    #  8=FIX.4.4|9=128|35=D|49=xxx|56=LMXBL|...5684|10=166|
    #  <---- hlen ----><------- body_length -------><--7-->
    hlen = sum(map(len, prefix_parts[0:2])) + 2
    return hlen + body_length + 7


class FIXMessageIn:
    def __init__(self, buffer):
        if type(buffer) is not bytes:
            raise TypeError("wrong type")
        if len(buffer) < PEEK_SIZE:
            raise ValueError(
                "buffer too short to contain FIX message {}".format(buffer)
            )
        if not buffer[0:6] == b"8=FIX.":
            raise ValueError("BeginString[8] must be 1st field {}".format(buffer))

        # simple delimit by SOH in first 30 characters, since no
        # raw data tags/values can occur this early in the message
        prefix_parts = buffer[0:PEEK_SIZE].split(b"\001")

        # Simple tests for "garbled messages" from FIX44 vol2 page 29
        try:
            self.version = fixversion_decode[
                prefix_parts[0]
            ]  # validate FIX Version from BeginString[8]
        except Exception:
            raise ValueError(
                "BeginString not a valid FIX implementation, try: {}".format(
                    fixversion_decode.keys()
                )
            )
        if not prefix_parts[1][0:2] == b"9=":
            raise ValueError("Bodylength[9] must be 2nd field {}".format(buffer))
        if not prefix_parts[2][0:3] == b"35=":
            raise ValueError("MsgType[35] must be 3rd field {}".format(buffer))
        body_length = int(prefix_parts[1][2:])  # TODO: byte to int?
        if not buffer[-1:] == b"\x01":  # |10=xxx|
            raise ValueError("Checksum[10] missing trailing SOH {}".format(buffer))
        if not buffer[-8:-4] == b"\x0110=":  # |10=xxx|
            raise ValueError(
                "Checksum[10] must be last field in buffer {}".format(buffer)
            )

        self.msg_type = prefix_parts[2][3:].decode("cp1252")
        self.buffer = buffer

        # Data Integrity - FIX44 vol2 page 4
        # The integrity of message data can be verified in two ways:
        # verification of message length and a checksum. The message
        # length is indicated in the BodyLength field and is verified
        # by counting the number of characters in the message following
        # the BodyLength field up to, and including, the delimiter
        # immediately preceding the CheckSum tag (10=).
        # The CheckSum integrity check is calculated by summing the
        # binary value of each character from the 8 of '8='' up to and
        # including the <SOH> character immediately preceding the CheckSum
        # tag field and comparing the least significant eight bits of the
        # calculated value to the CheckSum value.

        # validate length: msgtype tag to checksum 10=
        #  8=FIX.4.4|9=128|35=D|49=xxx|56=LMXBL|...5684|10=166|
        #  <---- hlen ----><------- body_length -------><--7-->
        hlen = sum(map(len, prefix_parts[0:2])) + 2
        cont = buffer[0:-7]
        chk_desired = sum(cont) % 256
        chk_given = int(buffer[-4:-1])

        logging.debug(
            "FIX inbound msg: ver={} body len={} hlen={} checksum "
            "desired={} given={} buffer: {}".format(
                self.version, body_length, hlen, chk_desired, chk_given, buffer
            )
        )
        expected_len = hlen + body_length + 7
        if not expected_len == len(buffer):
            should_be = len(buffer) - hlen - 7
            raise ValueError(
                "Bad BodyLength: tag 9={} implies {} bytes, "
                "buffer was {} bytes! (should be 9={}) msg: {}".format(
                    body_length, expected_len, len(buffer), should_be, buffer
                )
            )
        if not chk_given == chk_desired:
            raise ValueError(
                "Bad Checksum: calculated={} embedded={} buffer: {}".format(
                    chk_desired, chk_given, buffer
                )
            )

        # FIX Body parser
        # Now the length and checksum are good, iterate over the message picking up tag start and end positions.
        # If a data tag, we need to skip a number of bytes specified by the matching
        # data-length tag, that *should* have occured prior, since embedded SOH characters are permitted:
        # e.g.    '8=FIX...35=A|95=11|96=HELLO|WORLD|10=560|' should parse as
        #    96=HELLO|WORLD
        #    10=560
        self.tags = []
        self._session_tags = []
        in_tag_value = False  # needed to allow '=' in tag values
        tag_start = 0
        tag_data_start = -1
        tag = None
        i = 0
        datatag_known_lengths = {}
        while i < len(buffer):
            if buffer[i] == 61 and not in_tag_value:
                tag = int(buffer[tag_start:i])
                in_tag_value = True
                tag_data_start = i + 1
                if tag in data_length_to_tag.values():
                    try:
                        # jump straight to SOH using known length
                        i = i + datatag_known_lengths[tag]
                    except Exception:
                        raise ValueError(
                            "No data-length tag {} found preceeding data tag {}:\n{}".format(
                                data_tag_to_length[tag], tag, buffer
                            )
                        )
            elif buffer[i] == 0x01 and in_tag_value:
                tag_tuple = (tag, tag_data_start, i)
                content = buffer[tag_tuple[1] : tag_tuple[2]]
                # print(' >> {}  = {}'.format(tag, content))
                if tag in data_length_to_tag.keys():
                    # print('got data tag length {} with value {}'.format(tag, content))
                    datatag_known_lengths[data_length_to_tag[tag]] = int(content)
                elif tag in session_tags:
                    self._session_tags.append(tag_tuple)
                else:
                    self.tags.append(tag_tuple)
                # store various session tags useful for seqnum processing
                if tag == 34:
                    self.seqnum = int(content)
                # TODO: PossDup
                # TOOD: PossResend
                in_tag_value = False
                tag_start = i + 1
            i = i + 1

    def __iter__(self):
        "Iterate over the application-level tags in this message"
        value = FIXValue(self.buffer)
        for tagposition in self.tags:
            yield value.position(*tagposition)

    def session_tags(self):
        "Iterate over the session-level tags in this message"
        value = FIXValue(self.buffer)
        for tagposition in self._session_tags:
            yield value.position(*tagposition)


class FIXBuilder:
    # Assemble a FIX message for sending
    def __init__(self, version, components, clock, msgtype, msgseqnum):
        if len(msgtype) not in [1, 2]:
            raise ValueError("Bad message type, must be 1 or 2 chars")
        self.fields = []
        self.version = version
        self.append(35, msgtype)
        for k, v in components:
            self.append(k, v)
        self.append(34, msgseqnum)
        self.append_datetime(52, clock)

    def finish(self):
        body = b"".join(
            [
                str(tag).encode("utf-8") + b"=" + value + b"\001"
                for (tag, value) in self.fields
            ]
        )
        msglen = len(body)
        buffer = (
            fixversion_encode[self.version]
            + b"\0019="
            + str(msglen).encode("utf-8")
            + b"\001"
            + body
        )
        checksum = sum(buffer) % 256
        buffer = buffer + b"10=" + "{:03}".format(checksum).encode("utf-8") + b"\001"
        return FIXMessageIn(buffer)

    def append_bytes(self, tag, value):
        if type(value) is not bytes:
            raise TypeError("Value must be bytes")
        if type(tag) is not int:
            raise TypeError("Tag must be int")
        data_tag_length_tag = data_tag_to_length.get(tag)
        if data_tag_length_tag:
            self.append_int(data_tag_length_tag, len(value))
        elif "\001" in value:
            raise ValueError(
                "Cannot have SOH character in non-data tag {}, value {}".format(
                    tag, value
                )
            )
        self.fields.append((tag, value))

    def append_int(self, tag, value):
        raw = str(value).encode("utf-8")
        self.fields.append((tag, raw))

    def append_datetime(self, tag, value=time.time):
        # value should be a time.time() integer value
        if callable(value):
            value = value()
        if type(value) is not float:
            raise TypeError(
                "timestamp must be seconds since midnight UTC 1970 "
                "from time.time() not {}".format(type(value))
            )
        fmt = time.strftime("%Y%m%d-%H:%M:%S.000", time.gmtime(value))
        self.append(tag, fmt)  # '20150213-15:05:44.079'

    def append(self, tag, value):
        if type(value) in [int, str, float]:
            self.append_int(tag, value)
        elif type(value) is bytes:
            self.append_bytes(tag, value)
        else:
            raise TypeError("No encoder for type {}".format(type(value)))
