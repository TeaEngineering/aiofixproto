import collections
import itertools
from typing import Optional, Any, Callable
import inflection
from aiofix.message import FIXMessageIn, FIXValue

"""
FIXValidators take wire message (FIXMessageIn) delimited fields and produce
a json object representing the message. Required tags and permitted values are
validated. Repeating groups are parsed and checked for consistency. Extranious
tags are rejected.

Exceptions are raised if the message does not follow spec, and can be caught to
generate decent Reject/BMR messages.
"""


class RejectError(RuntimeError):
    def __init__(self, message: str, fixMsg: FIXMessageIn, sessionRejectReason: Optional[int]=None, refTagID: Optional[int]=None):
        super().__init__(message)
        self.fixMsg = fixMsg
        self.refTagID = None
        self.sessionRejectReason = sessionRejectReason


class BusinessRejectError(RuntimeError):
    def __init__(self, message: str, fixMsg: FIXMessageIn, ref_id: str="N/A", reject_reason: int=0):
        super().__init__(message)
        self.fixMsg = fixMsg
        self.reject_ref_id = ref_id
        self.reject_reason = reject_reason


class Field:
    def __init__(self, tag: int, optional: bool=False):
        self.optional = optional
        self.tag = int(tag)
        self._known_as = str(tag)
        self.dict_key = "tag{}".format(self.tag)

    def known_as(self, known_as: str) -> "Field":
        self._known_as = known_as
        self.dict_key = inflection.underscore(known_as)
        return self

    def get_value(self, value_bytes: bytes) -> Any:
        return value_bytes.decode("utf-8")

    def parse(self, value_bytes: bytes, parsed_dict: dict[str, Any], parser: "Message") -> "Message":
        # add our own data to dict, and return (or substitute) parser for next tag
        parsed_dict[self.dict_key] = self.get_value(value_bytes)
        return parser

    def print(self, print_callable: Callable[[str],None]=print, depth: int=0) -> None:
        flags = "?" if self.optional else ""
        dent = " |" * depth
        print_callable(
            f"  {dent}{self.tag:<4}{flags:2} {self._known_as:20} {self.dict_key:26} {type(self).__name__:26}"
        )


class CharField(Field):
    def __init__(self, tag: int, optional: bool=False, values: Optional[list[str]] = None):
        self.values = values
        super().__init__(tag, optional)

    def get_value(self, value_bytes: bytes) -> Any:
        v = value_bytes.decode("utf-8")
        if self.values:
            if v not in self.values:
                raise ValueError("expected {}".format(",".join(self.values)))
        return v


class StringField(CharField):
    pass


class TimestampField(CharField):
    pass


class IntField(Field):
    def __init__(self, tag: int, optional: bool=False, values: Optional[list[str]] = None, min: int=-pow(10, 10), max: int=pow(10, 10)):
        self.values = values
        self.min = min
        self.max = max
        super().__init__(tag, optional)

    def get_value(self, value_bytes: bytes) -> Any:
        v = int(value_bytes.decode("utf-8"))
        if v < self.min:
            raise ValueError("Minimum value {}".format(self.min))
        if v > self.max:
            raise ValueError("Maximum value {}".format(self.max))
        return v


class FloatField(Field):
    def __init__(self, tag: int, optional: bool=False, values: Optional[list[str]] = None, min: int=-pow(10, 10), max: int=pow(10, 10)):
        self.values = values
        self.min = min
        self.max = max
        super().__init__(tag, optional)

    def get_value(self, value_bytes: bytes) -> Any:
        v = float(value_bytes.decode("utf-8"))
        if v < self.min:
            raise ValueError("Minimum value {}".format(self.min))
        if v > self.max:
            raise ValueError("Maximum value {}".format(self.max))
        return v


class Message:
    """Fields in a message may be ordered (call set_ordered(True) to apply this) in which case:
    fields added 141,553,554 would match the following
       141=Y|553=user|554=password
    if field 553 was created with optional=True, then
       141=Y|554=password   would match, but
       554=password|141=Y   would be rejected.
    The implementation looks at the incoming tags, and maintains an index into the order
    array. If a field is in-place, we advance the index. Otherwise, look if skipping
    optional fields would get us back on track. If an optional field occurs behind
    the current position, or we would need to skip a non-optional field, raise an exception
    """

    def __init__(self, msg_type: str, msg_name: str, ordered: bool=False):
        self.msg_type = msg_type
        self.msg_name = msg_name
        self.dict_key = inflection.underscore(msg_name)
        self._fields: list[Field] = []
        self._field_dict: dict[int, Field] = {}
        self._ordered = ordered

        # parser state reset between on_enter and on_exit
        # TODO: parsing is not re-enterant
        self._required: dict[int, Field] = {}
        self._fixmsg: Optional[FIXMessageIn] = None

    def add_field_parser(self, field_parser: Field) -> None:
        if self._field_dict.pop(field_parser.tag, None):
            raise RuntimeError("Duplicate parser for tag {0.tag}".format(field_parser))
        self._fields.append(field_parser)
        self._field_dict[field_parser.tag] = field_parser
        # pre-compute descriptive ordering for error messages
        self._fieldorder_desc = ", ".join(
            [str(f.tag) + ("?" if f.optional else "") for f in self._fields]
        )

    def set_ordered(self, ordered: bool) -> None:
        # check all fields mentioned exist, and if we are setting an order that
        # all fields are mentioned.
        self._ordered = ordered

    def parse_msg(self, fixmsg: FIXMessageIn, datadict: dict[str, Any]) -> None:
        msg_parser = self
        msg_parser.on_enter(fixmsg, datadict)
        for field in fixmsg:
            try:
                # do we have a field-parser matching this field?
                field_parser, msg_parser = msg_parser.get_field_parser(field.tag)
                msg_parser._check_position(field, field_parser, fixmsg)

                # parse field and populate into data_dict
                try:
                    msg_parser = msg_parser.parse_field(field_parser, field.bytes())
                except ValueError as v:
                    vm = ": {}".format(v.args[0]) if v.args[0] else ""
                    raise BusinessRejectError(
                        "Incorrect value {0.tag}={2} ({0._known_as}) in {1.msg_name}[{1.msg_type}] "
                        "message{3}".format(field_parser, self, field.value(), vm),
                        fixmsg,
                    )
            except KeyError:
                raise RejectError(
                    "Unexpected tag {0} found in {1} message".format(
                        field.tag, self.msg_name
                    ),
                    fixmsg,
                    2,
                    refTagID=field.tag,
                )
        msg_parser.on_exit()

    def get_field_parser(self, tag: int) -> tuple[Field, "Message"]:
        return self._field_dict[tag], self

    def parse_field(self, field_parser: Field, field_bytes: bytes) -> "Message":
        return field_parser.parse(field_bytes, self._dd, self)

    def on_enter(self, fixmsg: FIXMessageIn, datadict: dict[str,Any]) -> None:
        self._required = {  field.tag: field for field in self._fields if not field.optional}
        self._fixmsg = fixmsg
        self._dd = datadict
        self._position_iter = enumerate(self._fields)

    def _check_position(self, field: FIXValue, field_parser: Field, fixmsg: FIXMessageIn) -> None:
        self._required.pop(field.tag, None)
        # validate ordering (optional, but mandatory in repeating groups)
        if not self._ordered:
            return

        while True:
            try:
                pos, next_expected = next(self._position_iter)
                if next_expected.tag == field.tag:
                    self._check_position_at(pos, next_expected)
                    break
                else:
                    if not next_expected.optional:
                        raise RejectError(
                            "Field {0.tag} ({0._known_as}) out of order, expected {1.tag} ({1._known_as})"
                            " in {2.msg_name}[{2.msg_type}] message".format(
                                field_parser, next_expected, self
                            ),
                            fixmsg,
                            14,
                            refTagID=field_parser.tag,
                        )
            except StopIteration:
                # reached end of ordered, must be optional field later than specified
                raise RejectError(
                    "Optional field {0.tag} ({0._known_as}) out of order, should be {1._fieldorder_desc}"
                    " in {1.msg_name}[{1.msg_type}] message".format(field_parser, self),
                    fixmsg,
                    14,
                    refTagID=field_parser.tag,
                )

    def _check_position_at(self, position: int, field: Field) -> None:
        pass

    def on_exit(self) -> None:
        # assert on_enter was called (mypy)
        assert self._fixmsg is not None

        # any missing required fields?
        if self._required:
            missing_field = list(self._required.values())[0]
            raise RejectError(
                "Required tag {0.tag} ({0._known_as}) missing in {1.msg_name}[{1.msg_type}] message".format(
                    missing_field, self
                ),
                self._fixmsg,
                1,
                refTagID=missing_field.tag,
            )

    def print(self, print_callable: Callable[[str],None]=print, depth: int=0) -> None:
        for field in self._fields:
            field.print(print_callable, depth)

    def __getitem__(self, tag_no: int) -> Field:
        return self._field_dict[tag_no]


class BaseFIXValidator:
    def __init__(self) -> None:
        self._built = False
        self._message_parsers: dict[str, Message] = {}

    def build(self) -> None:
        pass

    def validate(self, msg: FIXMessageIn) -> dict[str, Any]:
        if not self._built:
            self.build()
            self._built = True

        parser = self._message_parsers.get(msg.msg_type)
        if parser is None:
            raise RejectError("Unsupported MsgType {0.msg_type}".format(msg), msg, 11)
        datadict: dict[str,Any] = {}
        parser.parse_msg(msg, datadict)
        datadict["msg_type"] = parser.dict_key
        return datadict

    def print(self, print_callable:Callable[[str],None]=print) -> None:
        for k, v in self._message_parsers.items():
            print_callable("{0.msg_type:2} {0.msg_name}".format(v))
            v.print(print_callable, 0)
            print_callable("")

    def add_message_parser(self, parser: Message) -> None:
        if self._message_parsers.get(parser.msg_type, None):
            raise RuntimeError("Existing parser for {0.msg_type}".format(parser))
        self._message_parsers[parser.msg_type] = parser

    def __getitem__(self, tag: str) -> Message:
        return self._message_parsers[tag]


class RepeatingGroup(Message):
    def __init__(self, parent: Message, group_name: str="groupName"):
        Message.__init__(self, parent.msg_type, parent.msg_name, True)
        self._parent = parent
        self.group_name = group_name
        self.dict_key = inflection.underscore(group_name)

        # state between on_enter, on_exit
        self._parent_parser: Optional[Message] = None
        self._triggering_tag: Optional[Field] = None

    def set_ordered(self, ordered: bool) -> None:
        raise RuntimeError("Repeating groups must be ordered")

    def prepare_for_repeat(self, count: int, parent_parser: Message, rg_list: list[dict[str,Any]], triggeringTag: Field) -> None:
        assert parent_parser._fixmsg
        self._parent_parser = parent_parser
        self._count = count
        self._rg_list = rg_list
        self._triggering_tag = triggeringTag
        self.on_enter(parent_parser._fixmsg, {})
        self._position_iter = itertools.cycle(enumerate(self._fields))
        self._last_position = -1

    def get_field_parser(self, tag: int) -> tuple[Field, Message]:
        f = self._field_dict.get(tag)
        if f:
            return f, self
        # About to pop from this nesting depth, run inherited on_exit checks.
        # First check parent actually knows potentially-closing tag before unpoping,
        # as unknown tag error should be higher precidence that length mismatch.
        assert self._parent_parser
        x = self._parent_parser.get_field_parser(tag)
        self.repeating_exit()
        return x

    def repeating_exit(self) -> None:
        assert self._parent_parser is not None

        Message.on_exit(self)  # check required fields
        self.push_and_clear_dictionary()

        # validate length matches count
        if not self._count == len(self._rg_list):
            assert self._fixmsg
            assert self._triggering_tag
            raise RejectError(
                "Repeating Group '{0.group_name}' started by {0._triggering_tag.tag}"
                "={0._count} ({0._triggering_tag._known_as}) had {1} repeats, not "
                "{0._count}, in {2.msg_name}[{2.msg_type}] message".format(
                    self, len(self._rg_list), self._parent
                ),
                self._fixmsg,
                16,
            )

    def _check_position_at(self, position: int, field: Field) -> None:
        if not position > self._last_position:
            self.push_and_clear_dictionary()
        self._last_position = position

    def push_and_clear_dictionary(self) -> None:
        # we're about to loop the repeating group on next read
        if len(self._fields) == 1:
            self._rg_list.append(list(self._dd.values())[0])
        else:
            self._rg_list.append(self._dd)
        self._dd = {}

    def on_exit(self) -> None:
        # assert we are parsing (mypy)
        assert self._parent_parser

        # our repeating group is the last field in the message, so run our validation
        # then pass up to the parent parser
        self.repeating_exit()
        self._parent_parser.on_exit()


# use min=1 to enforce at least one repeating group
class RepeatingGroupLengthField(IntField):
    def __init__(self, tag: int, repeatingGroupParser: RepeatingGroup, min: int=0, max: int=pow(10, 10)):
        super().__init__(tag, min=min, max=max)
        self._repeatingGroupParser = repeatingGroupParser
        if not self._repeatingGroupParser.dict_key:
            raise RuntimeError("No dict_key set on RepeatingGroup")

    def parse(self, value_bytes: bytes, parsed_dict: dict[str, Any], parser: Message) -> Message:
        self._parentParser = parser
        count = self.get_value(value_bytes)
        rg_list: list[Any] = []
        parsed_dict[self._repeatingGroupParser.dict_key] = rg_list
        if count > 0:
            self._repeatingGroupParser.prepare_for_repeat(count, parser, rg_list, self)
            return self._repeatingGroupParser
        return parser

    def print(self, print_callable:Callable[[str],None]=print, depth: int=0) -> None:
        IntField.print(self, print_callable, depth)
        self._repeatingGroupParser.print(print_callable, depth + 1)
