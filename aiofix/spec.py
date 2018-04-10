import inspect

from aiofix.validator import BaseFIXValidator, Message, RepeatingGroup, RepeatingGroupLengthField
from aiofix.validator import CharField, IntField, StringField, Field

"""
A spec is a way to capture a fix specification document in code. The spec
can be converted to a validator by calling build()

ClassFIXSpec allows validator instances to be created using nested
python classes. This allows the 'spec' to be readable and easily modified,
and to inherit from other specs.
The build() method inspects the object tree, checks for correctness and returns
the corresponding validator.
"""

class ClassFIXSpec():
    def build(self):
        validator = BaseFIXValidator()
        for d in dir(self):
            o = getattr(self, d)
            if inspect.isclass(o) and not d == '__class__':
                # nest classes inside me are Messages, build them
                # print('{} {}'.format(d, type(o)))
                msgtype = None
                rpts = []
                fields = []
                for value in [x for x in dir(o) if not x.startswith('_')]:
                    o2 = getattr(o, value)
                    # print('  {} {}'.format(value, type(o2)))
                    if value == 'msgtype':
                        msgtype = o2
                    elif isinstance(o2, Field):
                        fields.append(o2.known_as(value))
                    elif type(o2) is type:
                        rpts.append((value, o2))
                    else:
                        raise RuntimeError("Unknown field/property {} {}".format(value, type(o2)))

                # create the message
                m = Message(msgtype, d)

                # setup repeating groups
                for k, v in rpts:
                    s = RepeatingGroup(m, k)

                    # pull out fields for the repeating group
                    rg_fields = {}
                    counter = 0
                    ordering = None
                    for value in [x for x in dir(v) if not x.startswith('_')]:
                        o2 = getattr(v, value)
                        if value == 'counter':
                            counter = o2
                        elif value == 'ordering':
                            ordering = o2
                        elif isinstance(o2, Field):
                            rg_fields[o2.tag] = o2.known_as(value)
                        else:
                            raise RuntimeError("Unknown field/property {} {}".format(value, type(o2)))
                    if not ordering:
                        raise RuntimeError("No ordering {} {}".format(value, type(o2)))
                    for tag in ordering:
                        s.add_field_parser(rg_fields.pop(tag))
                    if rg_fields:
                        raise RuntimeError("Field {} not in ordering".format(rg_fields.keys()))

                    no_syms = RepeatingGroupLengthField(counter[0], s).known_as(counter[1])
                    fields.append(no_syms)

                # add fields in order
                for f in fields:
                    m.add_field_parser(f)

                validator.add_message_parser(m)
        return validator

class FIX44BaseSpec(ClassFIXSpec):
    class Heartbeat():
        msgtype = '0'
        TestReqID = StringField(112, optional=True)

    class TestRequest():
        msgtype = '1'
        TestReqID = StringField(112)

    class ResendRequest():
        msgtype = '2'
        BeginSeqNo = IntField(7)
        EndSeqNo = IntField(16, optional=True)

    class Reject():
        msgtype = '3'
        RefSeqNum = IntField(45)
        RefTagID = IntField(371, optional=True)
        RefMsgType = StringField(372, optional=True)
        Text = StringField(58, optional=True)
        SessionRejectReason = StringField(373, optional=True)

    class SequenceReset():
        msgtype = '4'
        GapFillFlag = CharField(123, values=['Y', 'N'])
        NewSeqNo = IntField(36)

    class LogoutMessage():
        msgtype = '5'
        Text = StringField(58, optional=True)


class FIX44Spec(FIX44BaseSpec):
    class LogonMessage():
        msgtype = 'A'
        ResetSeqNum = CharField(141, values=['Y', 'N'], optional=True)
        Username = StringField(553, optional=True)  # optional as validator used in client too
        Password = StringField(554, optional=True)
        EncryptMethod = CharField(98, values=['0'])
        HeartbeatInt = IntField(108, min=1, max=120)
        Text = StringField(58, optional=True)
