import unittest
from aiofix.spec import FIX44Spec


class TestSpec(unittest.TestCase):
    def test_nestedclass_validator(self):
        bfv = FIX44Spec()
        v = bfv.build()
        v.print()
