
import unittest
from . import spec


class TestSpec(unittest.TestCase):
    def test_nestedclass_validator(self):
        bfv = spec.FIX44Spec()
        bfv.build()
        # bfv.print()
