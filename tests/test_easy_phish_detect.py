import unittest
from urllib.parse import urlparse

from easy_phish_detect import (
    URLValidationError,
    check_at_symbol,
    check_domain_age,
    check_https,
    check_hyphen,
    check_ip_in_url,
    check_url_length,
    validate_url,
)


class PhishingDetectorTests(unittest.TestCase):
    def test_detection_rules_handle_suspicious_url(self) -> None:
        url = "https://login-attacker.com@evil.co/" + "a" * 100

        self.assertFalse(check_ip_in_url(url))
        self.assertTrue(check_at_symbol(url))
        self.assertTrue(check_url_length(url))
        self.assertTrue(check_hyphen(url))
        self.assertTrue(check_https(url))

    def test_detection_rules_detect_long_url(self) -> None:
        self.assertTrue(check_url_length("https://" + "a" * 100))

    def test_validation_rejects_non_https_and_private_addresses(self) -> None:
        with self.assertRaises(URLValidationError):
            validate_url("http://example.com")
        with self.assertRaises(URLValidationError):
            validate_url("https://127.0.0.1")
        with self.assertRaises(URLValidationError):
            validate_url("https://[::1]")
        with self.assertRaises(URLValidationError):
            validate_url("https://user@example.com")

    def test_validation_rejects_invalid_and_overlong_urls(self) -> None:
        with self.assertRaises(URLValidationError):
            validate_url("not-a-url")
        with self.assertRaises(URLValidationError):
            validate_url("https://example.com/" + "a" * 4000)

    def test_validation_accepts_public_https_url(self) -> None:
        url = "https://example.com/path"
        self.assertEqual(validate_url(url), url)

    def test_domain_helpers_use_parsed_url(self) -> None:
        url = "https://login-attacker.com@evil.co"
        self.assertEqual(urlparse(url).netloc, "login-attacker.com@evil.co")
        self.assertTrue(check_hyphen("https://example-com.test"))
        self.assertFalse(check_hyphen("https://example.test"))

    def test_domain_age_returns_a_status(self) -> None:
        self.assertIn(check_domain_age("example.com"), {"Old or Registered", "Possibly New", "WHOIS Failed"})


if __name__ == "__main__":
    unittest.main()
