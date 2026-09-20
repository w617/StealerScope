"""Compatibility cases derived from documented public parser grammars."""
from pathlib import Path
import tempfile
import unittest

from stream_log_parser import StreamLogParser


class ExternalCompatibilityTests(unittest.TestCase):
    def parse(self, body, filename="Passwords.txt"):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, filename).write_text(body, encoding="utf-8")
            return StreamLogParser(folder).parse_logs_stream()

    def assert_record(self, body, expected):
        data = self.parse(body)
        self.assertEqual(len(data["credentials"]), 1, data["warnings"])
        for key, value in expected.items():
            self.assertEqual(data["credentials"][0].get(key), value)
        self.assertEqual(data["source_files"][0]["status"], "parsed")

    def test_application_metadata_is_preserved(self):
        self.assert_record(
            "Application: Chrome\nURL: https://example.test\nUsername: analyst\nPassword: test-only\n",
            {"soft": "Chrome", "url": "https://example.test", "username": "analyst", "password": "test-only"})

    def test_external_aliases(self):
        cases = [
            ("Storage: Chrome\nHostname: https://example.test\nUSER LOGIN: analyst\nUSER PASSWORD: test-only\n",
             {"soft": "Chrome", "url": "https://example.test", "username": "analyst", "password": "test-only"}),
            ("UR1: https://example.test\nU53RN4M3: analyst\nP455W0RD: test-only\n",
             {"url": "https://example.test", "username": "analyst", "password": "test-only"}),
        ]
        for body, expected in cases:
            with self.subTest(body=body.splitlines()[0]):
                self.assert_record(body, expected)

    def test_url_is_optional_when_credential_pair_exists(self):
        self.assert_record("Soft: Outlook\nLogin: analyst\nPassword: test-only\n",
                           {"soft": "Outlook", "username": "analyst", "password": "test-only"})

    def test_multiline_password_is_preserved(self):
        self.assert_record("URL: https://example.test\nUsername: analyst\nPassword: first-line\nsecond-line\nthird:line\n",
                           {"password": "first-line\nsecond-line\nthird:line"})

    def test_next_recognized_field_starts_adjacent_record(self):
        data = self.parse("URL: one\nUSER: a\nPASS: first\nApplication: Edge\nURL: two\nUSER: b\nPASS: second")
        self.assertEqual([(r.get("soft"), r["url"], r["password"]) for r in data["credentials"]],
                         [(None, "one", "first"), ("Edge", "two", "second")])

    def test_table_without_url_is_supported(self):
        data = self.parse("Application,Username,Password\nChrome,analyst,test-only\n", "export.csv")
        self.assertEqual(data["credentials"][0]["soft"], "Chrome")
        self.assertEqual(data["credentials"][0]["password"], "test-only")


if __name__ == "__main__":
    unittest.main()
