import unittest

import Ask


class FuzzScoringTests(unittest.TestCase):
    def setUp(self):
        self.baseline = {"status": 200, "len": 100, "body": "normal page"}

    def score(self, body, probe_payload="'vulnfinderprobeabc", marker="vulnfinderprobeabc"):
        return Ask.score_fuzz_response(
            self.baseline,
            {"status": 200, "len": 100, "body": body},
            probe_payload,
            marker,
        )

    def test_normal_script_tag_does_not_trigger_xss_or_reflection(self):
        score, reasons = self.score("<html><script src='/app.js'></script></html>")
        self.assertEqual(score, 0)
        self.assertEqual(reasons, [])

    def test_generic_warning_does_not_trigger_sql_error(self):
        score, reasons = self.score("<div>Warning: your session expires soon.</div>")
        self.assertEqual(score, 0)
        self.assertEqual(reasons, [])

    def test_marker_near_sql_error_is_scored(self):
        score, reasons = self.score(
            "SQL syntax error near 'vulnfinderprobeabc' in query"
        )
        self.assertEqual(score, 65)  # SQL error plus attributable reflection
        self.assertIn("SQL error associated with probe marker", reasons)

    def test_punctuation_in_normal_html_is_not_a_reflection(self):
        score, reasons = self.score("<input value=\"'\"><p>100%27 complete</p>")
        self.assertEqual(score, 0)
        self.assertEqual(reasons, [])

    def test_raw_unique_xss_probe_is_scored(self):
        marker = "vulnfinderprobeabc"
        probe = Ask.make_probe_payload("<script>alert(1)</script>", marker)
        score, reasons = self.score(f"<main>{probe}</main>", probe, marker)
        self.assertEqual(score, 70)  # reflection plus raw executable XSS probe
        self.assertIn("Raw XSS probe reflected in script context", reasons)


if __name__ == "__main__":
    unittest.main()
