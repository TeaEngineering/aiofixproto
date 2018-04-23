
from . import message
import unittest
import time


class TestIncomingMethods(unittest.TestCase):

    def test_well_formed_msg(self):
        # checksum test from https://stackoverflow.com/questions/32708068/how-to-calculate-checksum-in-fix-manually
        msg = message.from_delim('8=FIX.4.2|9=49|35=5|34=1|49=ARCA|52=20150916-04:14:05.306|56=TW|10=157|')
        self.assertEqual(msg.msg_type, '5')
        self.assertEqual(msg.seqnum, 1)
        self.assertEqual(msg.version, 42)
        # for k,v in msg.items():
        for field in msg:
            print('{}: {}'.format(field.tag, field.value))

        # Heartbeating
        msg = message.from_delim('8=FIX.4.4|9=54|35=0|49=LMXBL|56=xxx|34=2105|52=20150213-15:05:44.079|10=084|')
        self.assertEqual(msg.seqnum, 2105)
        self.assertEqual(msg.msg_type, '0')
        msg = message.from_delim('8=FIX.4.4|9=50|35=0|49=xxx|56=LMXBL|34=2029|52=20150213-15:05:44|10=135|')

    def test_peek_length(self):
        # checksum test from https://stackoverflow.com/questions/32708068/how-to-calculate-checksum-in-fix-manually
        msg = message.from_delim('8=FIX.4.2|9=49|35=5|34=1|49=ARCA|52=20150916-04:14:05.306|56=TW|10=157|')

        self.assertEqual(message.peek_length(msg.buffer), len(msg.buffer))
        self.assertEqual(message.peek_length(msg.buffer[0:35]), len(msg.buffer))
        self.assertEqual(message.peek_length(msg.buffer[0:10]), -1)

        # sweep over the full range to catch oob
        for i in range(0, 25):
            r = message.peek_length(msg.buffer[0:i])
            if r < 0:
                self.assertEqual(r, -1)  # more input needed
            else:
                self.assertEqual(message.peek_length(msg.buffer), len(msg.buffer))

    def test_msglen(self):
        with self.assertRaisesRegex(ValueError, 'Bad BodyLength'):
            message.from_delim('8=FIX.4.2|9=48|35=5|34=1|49=ARCA|52=20150916-04:14:05.306|56=TW|10=157|')

    def test_checksum(self):
        with self.assertRaisesRegex(ValueError, 'Bad Checksum'):
            message.from_delim('8=FIX.4.2|9=48|35=5|34=1|49=CAR|52=20150916-04:14:05.306|56=TW|10=157|')

    def test_fixver(self):
        with self.assertRaisesRegex(ValueError, 'BeginString not.*valid'):
            message.from_delim('8=FIX.4.9|9=48|35=5|34=1|49=CAR|52=20150916-04:14:05.306|56=TW|10=157|')

    def test_data_tags(self):
        # testcase - data tag #96 (with length tag #95) containing embedded SOH
        msg = message.from_delim('8=FIX.4.4|9=68|35=A|49=x|56=y|34=1|52=20150215-22:01:05|95=11|96=HELLO|'
                                 'WORLD|141=Y|10=237|')
        for field in msg:
            if field.tag == 96:
                self.assertEqual(field.bytes(), b'HELLO\001WORLD')
                break
        else:
            self.fail('tag 96 missing')
        for field in msg:
            if field.tag == 141:
                self.assertEqual(field.value(), 'Y')
                break
        else:
            self.fail('tag 141 missing')
        # must be in message order. 95 has been absorbed by parsing layer
        self.assertListEqual([field.tag for field in msg], [96, 141])

        with self.assertRaisesRegex(ValueError, 'No data-length tag 95 found preceeding data tag 96'):
            message.from_delim('8=FIX.4.4|9=62|35=A|49=x|56=y|34=1|52=20150215-22:01:05|96=HELLO|'
                               'WORLD|141=Y|10=217|')

    def test_tag_iterator_no_session(self):
        # Logon
        msg = message.from_delim('8=FIX.4.4|9=89|35=A|49=xxx|56=LMXBL|34=1|52=20150215-22:01:05|'
                                 '98=0|108=30|141=Y|553=xxx|554=###########|10=231|')

        self.assertListEqual([field.tag for field in msg], [98, 108, 141, 553, 554])

    def test_market_data(self):
        # Market Data Request
        message.from_delim(
                '8=FIX.4.4|9=1142|35=V|34=2|49=xxx|52=20141211-'
                '08:55:54|56=LMXBLM|262=20141211-'
                '08_55_54|263=1|264=1|265=0|267=2|269=0|269=1|146=71|48=4001|22=8|48=4008|22=8|'
                '48=4007|22=8|48=4009|22=8|48=4016|22=8|48=4015|22=8|48=4011|22=8|48=4003|22=8|'
                '48=4006|22=8|48=4001|22=8|48=4017|22=8|48=4014|22=8|48=4012|22=8|48=4005|22=8|'
                '48=4002|22=8|48=4013|22=8|48=4010|22=8|48=4004|22=8|48=100479|22=8|48=100481|'
                '22=8|48=100483|22=8|48=100485|22=8|48=100487|22=8|48=100489|22=8|48=100491|22'
                '=8|48=100493|22=8|48=100495|22=8|48=100497|22=8|48=100499|22=8|48=100501|22='
                '8|48=100503|22=8|48=100505|22=8|48=100507|22=8|48=100509|22=8|48=100511|22=8|'
                '48=100513|22=8|48=100515|22=8|48=100517|22=8|48=100519|22=8|48=100521|22=8|48'
                '=100523|22=8|48=100525|22=8|48=100527|22=8|48=100529|22=8|48=100531|22=8|48='
                '100533|22=8|48=100535|22=8|48=100537|22=8|48=100539|22=8|48=100541|22=8|48=10'
                '0543|22=8|48=100545|22=8|48=100547|22=8|48=100613|22=8|48=100615|22=8|48=1006'
                '17|22=8|48=1006'
                '19|22=8|48=100667|22=8|48=100671|22=8|48=100669|22=8|48=100673|22=8|48=100675'
                '|22=8|48=100093|22=8|48=100677|22=8|48=100637|22=8|48=100639|22=8|48=100097|2'
                '2=8|48=100806|22=8|48=100807|22=8|48=100679|22=8|48=100681|22=8|10=105|')

        # Market Data update
        # msg2 = message.from_delim('8=FIX.4.4|9=181|35=W|49=LMXBLM|56=xxx|34=2|52=20141211-'
        #       '08:55:53.459|262=20141211-'
        #       '08_55_54|48=100097|22=8|268=2|269=0|270=9855.2|271=20|272=20141211|273=08:55:'
        #       '53.261|269=1|270=9856.7|271=30|10=033|')
    def test_order_status(self):
        # OrderStatusRequest
        message.from_delim('8=FIX.4.4|9=82|35=H|49=xxx|56=LMXBL|34=2|52=20150220-10:17:54.279|'
                           '11=57080.5|48=100637|22=8|54=2|10=107|')

    def test_documentation_messages(self):
        message.from_delim(
            '8=FIX.4.4^9=129^35=A^49=ZX_WvYeEqZXyUFfyxwcs17l4^56=BitMEX^34=1^52=20170715-09:30:04'
            '^141=Y^553=ZX_WvYeEqZXyUFfyxwcs17l4^554=SECRETKEY^98=0^108=5^10=097^', delim='^')
        message.from_delim(
            '8=FIX.4.4^9=75^35=A^49=BitMEX^56=ZX_WvYeEqZXyUFfyxwcs17l4^34=1^52='
            '20170715-09:30:05^108=5^10=252^', delim='^')
# msg = message.from_delim('8=FIX.4.4|9=146|35=AD|34=3349|49=xxx|52=20150220-10:50:04.148|'
#       '56=LMXBL|263=0|568=390041488433|569=1|580=2|60=20150220-08:50:04.148|'
#       '60=20150220-10:50:04.148|10=081|')

# msg2 = message.from_delim('8=FIX.4.4^9=146^35=AD^34=3349^49=xxx^52=20150220-10:50:04.148^'
#       '56=LMXBL^263=0^568=390041488433^569=1^580=2^60=20150220-08:50:04.148^'
#       '60=20150220-10:50:04.148^10=081^', delim='^')

# What are some standard LMAX Exchange FIX messages?
# Trading

# New Order
# msg2 = message.from_delim('8=FIX.4.4|9=125|35=D|49=xxx|56=LMXBL|34=2028|52=20150213-15:05:14|11=54897|
#        18=H|22=8|38=1000|40=1|48=4001|54=1|59=0|60=20150213-15:05:14.084|10=113|')
# Execution Report
# msg2 = message.from_delim('8=FIX.4.4|9=212|35=8|49=LMXBL|56=xxx|34=2091|52=20150213-' +
#       '15:05:14.077|1=1820613222|11=54897|48=4001|22=8|54=1|37=AAGJHQAAAAJwThP5|5' +
#       '9=3|40=1|60=20150213-15:05:14.077|6=0|17=bIRaZgAAAALC2TsW|527=0|39=0|150=0|14=0|151=1000|38=1000|' +
#       '10=167|')

# OrderCancelRequest
# msg2 = message.from_delim('8=FIX.4.4|9=157|35=F|49=xxx|56=LMXBL|34=320814|52=20150220-'
#       '09:15:03.524|41=1424379907-310727|11=1424379907-'
#       '310733|48=100889|22=8|54=1|60=20150220-09:15:03.524|38=10|10=150|')

# OrderCancelReplaceRequest
# msg2 = message.from_delim('8=FIX.4.4|9=183|35=G|34=169077|49=xxx|52=20150220-'
#       '09:14:42.661|56=LMXBL|11=Feb20026604DAX1|18=Q|22=8|38=50|40=2|41='
#       'Feb20026604DAX1|44=10986.3|48=100097|54=1|59=0|60=20150220-'
#       '09:14:42.660|10=018|')


# TradeCaptureReport
# msg2 = message.from_delim('8=FIX.4.4|9=146|35=AD|34=3349|49=xxx|52=20150220-'
#       '10:50:04.148|56=LMXBL|263=0|568=390041488433|569=1|580=2|60=20150220-'
#       '08:50:04.148|60=20150220-10:50:04.148|10=081|')

class TestOutgoingMethods(unittest.TestCase):
    def test_send(self):

        class dummy_session():
            def __init__(self):
                self.version = 44
                self.senderCompID = 'BitMEX'
                self.targetCompID = 'xxx'
                self.lastOutbound = 45

            def get_and_increment_outbound():
                self.lastOutbound = self.lastOutbound + 1
                return self.lastOutbound

        class dummy_connection():
            def __init__(self):
                self.clock = time.time
                self.session = dummy_session()
        c = dummy_connection()

        builder = message.builder_for_connection(c, msgtype='AE')
        builder.append(569, 1)
        builder.append(580, '2')
        builder.append_datetime(60, time.time())
        fm = builder.finish()

        self.assertEqual(fm.seqnum, 45)
        self.assertEqual(fm.msg_type, 'AE')

        with self.assertRaisesRegex(ValueError, 'Bad message type'):
            message.builder_for_connection(c, msgtype='AES')


if __name__ == '__main__':
    unittest.main()
