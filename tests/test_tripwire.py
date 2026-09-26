"""The end-of-week-1 tripwire, on six real bdk_wallet full scans captured against the honeypot."""
import os
import unittest

from attack.calibrate import tripwire

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class TripwireTest(unittest.TestCase):
    def test_real_bdk_capture(self):
        ok, report = tripwire(os.path.join(FIXTURES, "bdk-honeypot-log.json"),
                              os.path.join(FIXTURES, "bdk-capture-truth.json"))
        self.assertTrue(ok, report)


if __name__ == "__main__":
    unittest.main()
