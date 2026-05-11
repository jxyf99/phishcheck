import unittest

from phishing_detector import analyze_text, registered_domain


class PhishingDetectorTests(unittest.TestCase):
    def test_empty_input_returns_guidance(self):
        result = analyze_text("")

        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "No content")
        self.assertEqual(result["findings"][0]["severity"], "info")

    def test_safe_message_has_no_obvious_risk(self):
        result = analyze_text("Team lunch is Friday at noon. Agenda is in the calendar invite.")

        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "No obvious risk")
        self.assertEqual(result["findings"][0]["category"], "Clean scan")

    def test_obvious_phish_scores_high_with_structured_findings(self):
        text = (
            "URGENT: your account will be suspended within 24 hours. "
            "Verify your password now at http://paypa1-login-security.top/verify-account "
            "or reply with your security code."
        )

        result = analyze_text(text)
        categories = {finding["category"] for finding in result["findings"]}

        self.assertGreaterEqual(result["score"], 75)
        self.assertIn("Credential request", categories)
        self.assertIn("Brand impersonation", categories)
        self.assertIn("Credential path", categories)
        self.assertTrue(all("message" in finding for finding in result["findings"]))

    def test_registered_domain_handles_common_multi_part_suffixes(self):
        self.assertEqual(registered_domain("login.paypal.co.uk"), "paypal.co.uk")
        self.assertEqual(registered_domain("alerts.service.gov.uk"), "service.gov.uk")
        self.assertEqual(registered_domain("secure.example.com"), "example.com")

    def test_mismatched_link_uses_registered_domain_comparison(self):
        text = '<a href="https://secure.evil.co.uk/login">https://paypal.co.uk/login</a>'

        result = analyze_text(text)
        messages = " ".join(result["reasons"])

        self.assertIn("different domain", messages)
        self.assertGreaterEqual(result["score"], 18)

    def test_punycode_domains_are_flagged(self):
        result = analyze_text("Please sign in at https://xn--paypl-3ve.com/login")
        messages = " ".join(result["reasons"])

        self.assertIn("punycode", messages.lower())
        self.assertGreater(result["score"], 0)

    def test_url_only_brand_lookalike_can_score_dangerous(self):
        result = analyze_text("http://paypa1-login-security.top/verify-account")

        self.assertGreaterEqual(result["score"], 70)
        self.assertEqual(result["level"], "High risk")


if __name__ == "__main__":
    unittest.main()
