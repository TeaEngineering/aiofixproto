
from . import message, validator
import re
import unittest


class TestValidators(unittest.TestCase):
    def test_data_types(self):
        testField = validator.StringField(324)
        testField.known_as('test')
        data_dict = {}
        testField.parse(b'HI', data_dict, None)

        testField = validator.IntField(345)
        testField.known_as('testnum')
        testField.parse(b'56', data_dict, None)

        self.assertEqual(data_dict, {'test': 'HI', 'testnum': 56})

    def test_msg_validate(self):
        msg = message.from_delim('8=FIX.4.2|9=49|35=A|34=1|49=ARCA|52=20150916-04:14:05.306|56=TW|10=169|')

        # either:
        #   1) suceeds returning a parsed data structure
        #   2) Raises RejectError
        #       0 = Invalid tag number
        #       1 = Required tag missing
        #       2 = Tag not defined for this message type
        #       9 = CompID problem
        #       11 = Invalid MsgType
        #       13 = Tag appears more than once
        #       14 = Tag specified out of required order
        #       15 = Repeating group fields out of order
        #       16 = Incorrect NumInGroup count for repeating group
        #   3) Raises BusinessMessageRejectError
        #       - this is done for application messages only
        #
        # When forming a 'Reject' message in reply, various details are needed:
        #  the Error object provides RefTagID, SessionRejectReason and Text.
        #   RefSeqnum and RefMsgType cna be populated from the message object
        #
        # 45 RefSeqNum Y MsgSeqNum of rejected message
        # 371 RefTagID N The tag number of the FIX field being referenced.
        # 372 RefMsgType N The MsgType of the FIX message being referenced.
        # 373 SessionRejectReason N Code to identify reason for a session-level Reject message.
        # 58 Text N Where possible, message to explain reason for rejection

        v = validator.BaseFIXValidator()
        with self.assertRaisesRegex(validator.RejectError, 'Unsupported MsgType A') as cm:
            data = v.validate(msg)
        self.assertEqual(cm.exception.sessionRejectReason, 11)

        m = validator.Message('A', 'Logon')
        v.add_message_parser(m)

        # Should parse OK as no application layer tags present
        data = v.validate(msg)
        self.assertEqual(data, {'msg_type': 'logon'})

        # Add Username tag
        msg = message.from_delim('8=FIX.4.2|9=70|35=A|34=1|49=ARCA|553=chris|554=secret|52='
                                    '20150916-04:14:05.306|56=TW|10=249|')
        with self.assertRaisesRegex(validator.RejectError, 'Unexpected tag 553 found in Logon message') as cm:
            data = v.validate(msg)
        self.assertEqual(cm.exception.sessionRejectReason, 2)

        # add required username field
        username_field = validator.StringField(553, optional=False)
        username_field.known_as('Username')
        m.add_field_parser(username_field)

        with self.assertRaisesRegex(validator.RejectError, 'Unexpected tag 554 found in Logon message') as cm:
            data = v.validate(msg)
        self.assertEqual(cm.exception.sessionRejectReason, 2)

        # add required password field
        password_field = validator.StringField(554, optional=False)
        password_field.known_as('Password')
        m.add_field_parser(password_field)

        resetseqno_field = validator.CharField(141, optional=True, values=['Y', 'N'])
        resetseqno_field.known_as('ResetSeqNumFlag')
        m.add_field_parser(resetseqno_field)

        data = v.validate(msg)
        self.assertEqual(data, {'msg_type': 'logon', 'username': 'chris', 'password': 'secret'})

        # Check population of optional field (141=Y)
        msg = message.from_delim('8=FIX.4.2|9=76|35=A|34=1|49=ARCA|141=Y|553=chris|554=secret|52='
                                    '20150916-04:14:05.306|56=TW|10=044|')
        data = v.validate(msg)
        self.assertEqual(data, {'msg_type': 'logon', 'username': 'chris', 'password': 'secret',
                                'reset_seq_num_flag': 'Y'})

        # Reject illegal value (141=Z)
        msg = message.from_delim('8=FIX.4.2|9=76|35=A|34=1|49=ARCA|141=Z|553=chris|554=secret|'
                                    '52=20150916-04:14:05.306|56=TW|10=045|')
        with self.assertRaisesRegex(validator.BusinessRejectError, 'Incorrect value 141=Z.*expected Y,N') as cm:
            data = v.validate(msg)

        # Reject message missing a required field
        msg = message.from_delim('8=FIX.4.2|9=59|35=A|34=1|49=ARCA|553=chris|52=20150916-04:14:05.306|56=TW|10=158|')
        with self.assertRaisesRegex(validator.RejectError, 'Required tag 554.*Logon') as cm:
            data = v.validate(msg)
        self.assertEqual(cm.exception.sessionRejectReason, 1)

    def test_dupe_message_parser(self):
        m = validator.Message('A', 'Logon')
        b = validator.Message('A', 'Logout')

        v = validator.BaseFIXValidator()
        with self.assertRaisesRegex(RuntimeError, 'Existing parser for A'):
            v.add_message_parser(m)
            v.add_message_parser(b)

    def test_msg_ordered(self):
        # Order: 553, 141?, 554
        m = validator.Message('A', 'Logon')
        m.add_field_parser(validator.StringField(553, optional=False).known_as('Username'))
        m.add_field_parser(validator.CharField(141, optional=True, values=['Y', 'N']).known_as('ResetSeqNumFlag'))
        m.add_field_parser(validator.StringField(554, optional=False).known_as('Password'))
        m.set_ordered(True)

        v = validator.BaseFIXValidator()
        v.add_message_parser(m)

        # check ordering. 1) 554 first
        msg = message.from_delim('8=FIX.4.2|9=76|35=A|34=1|49=ARCA|141=Z|554=secret|553=chris|52='
                                    '20150916-04:14:05.306|56=TW|10=045|')
        with self.assertRaisesRegex(
                validator.RejectError,
                re.escape('Field 141 (ResetSeqNumFlag) out of order, expected 553 (Username)')):
            data = v.validate(msg)

        # order 553,554 valid if 141 skipped, but 141 is present
        msg = message.from_delim('8=FIX.4.2|9=76|35=A|34=1|49=ARCA|553=chris|554=secret|141=Y|52='
                                    '20150916-04:14:05.306|56=TW|10=044|')
        with self.assertRaisesRegex(validator.RejectError, 'Optional field 141 .* out of order.*553, 141.*'):
            data = v.validate(msg)

        # valid ordering
        msg = message.from_delim('8=FIX.4.2|9=76|35=A|34=1|49=ARCA|553=chris|141=Y|554=secret|52='
                                    '20150916-04:14:05.306|56=TW|10=044|')
        data = v.validate(msg)
        self.assertEqual(data, {'msg_type': 'logon', 'username': 'chris', 'password': 'secret',
                                'reset_seq_num_flag': 'Y'})

    def test_repeating_group_optional_fields(self):
        # this test exercises that optional fields in a repeating group can be skipped. So long as
        # one field in the repeating group is mandatory, we use this to detect crossing into the
        # next 'repeat' of the repeating group.
        msg = message.from_delim(
                '8=FIX.4.4^9=154^35=W^49=BitMEX^56=qBkO5YQPsW1BwqTwXXFW7HPu^34=6^52=20170921-16:05:05.000^'
                '262=15e4c9106c^55=XBTUSD^268=2^'
                '269=0^270=3721.7^271=100^'
                '269=1^270=3721.8^271=200^10=083^', delim='^')

        m = validator.Message('W', 'MarketDataSnapshot')
        m.add_field_parser(validator.StringField(262).known_as('req_id'))
        m.add_field_parser(validator.StringField(55).known_as('symbol'))

        s = validator.RepeatingGroup(m, 'MDEntries')
        s.add_field_parser(validator.CharField(269, optional=False).known_as('MDEntryType'))
        s.add_field_parser(validator.FloatField(270, optional=True).known_as('MDEntryPx'))
        s.add_field_parser(validator.FloatField(271, optional=True).known_as('MDEntrySz'))
        s.add_field_parser(validator.StringField(278, optional=True).known_as('MDEntryID'))
        no_syms = validator.RepeatingGroupLengthField(268, s).known_as('NoEntries')

        m.add_field_parser(no_syms)

        v = validator.BaseFIXValidator()
        v.add_message_parser(m)

        data = v.validate(msg)

        self.assertEqual(data, {'req_id': '15e4c9106c', 'symbol': 'XBTUSD', 'md_entries': [
            {'md_entry_type': '0', 'md_entry_px': 3721.7, 'md_entry_sz': 100.0},
            {'md_entry_type': '1', 'md_entry_px': 3721.8, 'md_entry_sz': 200.0}
            ], 'msg_type': 'market_data_snapshot'})

    def test_repeating_group_embed(self):

        m = validator.Message('S', 'MarketDataSubscribe')
        m.add_field_parser(validator.StringField(553, optional=False).known_as('Before'))

        s = validator.RepeatingGroup(m, 'symbols')
        s.add_field_parser(validator.StringField(55, optional=False).known_as('Symbol'))
        no_syms = validator.RepeatingGroupLengthField(57, s).known_as('NoSymbols')

        m.add_field_parser(no_syms)
        m.add_field_parser(validator.StringField(554, optional=False).known_as('After'))
        m.set_ordered(True)

        v = validator.BaseFIXValidator()
        v.add_message_parser(m)

        # check ordering. 1) 554 first, colapsed repeating group
        msg = message.from_delim('8=FIX.4.2|9=80|35=S|34=1|49=ARCA|553=one|57=2|55=A|55=B|'
                                    '554=two|52=20150916-04:14:05.306|56=TW|10=184|')
        data = v.validate(msg)
        self.assertEqual(data, {'msg_type': 'market_data_subscribe', 'before': 'one', 'after':
                                'two', 'symbols': ['A', 'B']})

        # repeating group with multiple values in group
        s.add_field_parser(validator.IntField(58, optional=False).known_as('Type'))
        msg = message.from_delim('8=FIX.4.2|9=90|35=S|34=1|49=ARCA|553=one|57=2|55=A|58=1|'
                                    '55=B|58=2|554=two|52=20150916-04:14:05.306|56=TW|10=114|')
        data = v.validate(msg)
        self.assertEqual(data, {'msg_type': 'market_data_subscribe', 'before': 'one', 'after': 'two',
                                'symbols': [{'symbol': 'A', 'type': 1}, {'symbol': 'B', 'type': 2}]})

    def test_repeating_group_bare(self):
        # Test repeating with no header/trailer tag
        m = validator.Message('U', 'MarketDataUnsubscribe')
        s = validator.RepeatingGroup(m, 'Symbols')
        s.add_field_parser(validator.StringField(55, optional=False).known_as('Symbol'))
        no_syms = validator.RepeatingGroupLengthField(57, s).known_as('NoSymbols')
        m.add_field_parser(no_syms)

        v = validator.BaseFIXValidator()
        v.add_message_parser(m)

        msg = message.from_delim('8=FIX.4.2|9=69|35=U|34=1|49=ARCA|57=3|55=A|55=B|55=C|52='
                                    '20150916-04:14:05.306|56=TW|10=090|')
        data = v.validate(msg)
        self.assertEqual(data, {'msg_type': 'market_data_unsubscribe', 'symbols': ['A', 'B', 'C']})

        # check empty group
        msg = message.from_delim('8=FIX.4.2|9=54|35=U|34=1|49=ARCA|57=0|52=20150916-04:14:05.306|56=TW|10=147|')
        data = v.validate(msg)
        self.assertEqual(data, {'msg_type': 'market_data_unsubscribe', 'symbols': []})

        # check repeating group length mismatch 2!=3
        msg = message.from_delim('8=FIX.4.2|9=69|35=U|34=1|49=ARCA|57=2|55=A|55=B|55=C|52='
                                    '20150916-04:14:05.306|56=TW|10=089|')
        with self.assertRaisesRegex(
                validator.RejectError,
                re.escape("Repeating Group 'Symbols' started by 57=2 (NoSymbols) had 3 repeats, not 2, in "
                          "MarketDataUnsubscribe[U] message")) as cm:
            data = v.validate(msg)
            print(data)
        self.assertEqual(cm.exception.sessionRejectReason, 16)

        # v.print()



if __name__ == '__main__':
    unittest.main()
