import unittest

from aiofix import message
from aiofix.spec import FIX44BaseSpec, FIX44Spec
from aiofix.validator import CharField, IntField, StringField


class TestSpec(unittest.TestCase):
    def test_nestedclass_validator(self):
        bfv = FIX44Spec()
        v = bfv.build()
        v.print()


class DemoMDServerSpec(FIX44BaseSpec):
    class MarketDataRequest:
        msgtype = "V"
        MdReqID = StringField(262)
        SubscriptionRequestType = IntField(263, values=[1, 2])
        MarketDepth = IntField(264, values=[0, 1])
        MDUpdateType = IntField(265, values=[0, 1], optional=True)

        class MDEntryTypes:
            counter = 267, "NoMDEntryTypes"
            ordering = [269]
            EntryType = CharField(
                269, values=["0", "1", "2", "6", "7", "8", "9", "B", "C"]
            )

        class RelatedSym:
            counter = 146, "NoRelatedSym"
            ordering = [55]
            Symbol = StringField(55)


class TestMDSpec(unittest.TestCase):
    def test_nestedclass_validator(self):
        bfv = DemoMDServerSpec()
        v = bfv.build()
        v.print()

        msg = message.from_delim(
            "8=FIX.4.2|9=96|35=V|34=1|49=ARCA|262=r1|263=1|267=1|269=6|146=2|55=A|55=B|"
            "264=0|52=20150916-04:14:05.306|56=TW|10=080|"
        )
        data = v.validate(msg)
        self.assertEqual(
            data,
            {
                "market_depth": 0,
                "msg_type": "market_data_request",
                "md_entry_types": ["6"],
                "md_req_id": "r1",
                "related_sym": ["A", "B"],
                "subscription_request_type": 1,
            },
        )
