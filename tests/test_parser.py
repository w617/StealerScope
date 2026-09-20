import codecs
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from parser import LogParser
from stream_log_parser import StreamLogParser


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.parser = StreamLogParser(self.root)

    def write(self, name, text, encoding="utf-8"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding=encoding)
        return path

    def test_adjacent_records_aliases_and_eof(self):
        path = self.write("Passwords.txt", "browser: Chrome\nurl: https://one.test\nlogin: a\npassword: first\nURL: https://two.test\nUSER: b\nPASS: second")
        credentials = self.parser.parse_logs_stream()["credentials"]
        self.assertEqual([x["username"] for x in credentials], ["a", "b"])
        self.assertEqual([x["source_line"] for x in credentials], [1, 5])
        self.assertTrue(all(x["source"] == str(path) for x in credentials))

    def test_password_whitespace_colons_and_empty(self):
        self.write("all passwords.txt", "URL: x\nUSER: a\nPASS:  secret:part  \n\nURL: y\nUSER: b\nPASS:")
        self.assertEqual([x["password"] for x in self.parser.parse_logs_stream()["credentials"]], [" secret:part  ", ""])

    def test_bom_encodings(self):
        for encoding in ("utf-8-sig", "utf-16", "utf-32"):
            with self.subTest(encoding=encoding):
                self.write("all passwords.txt", "URL: x\nUSER: José\nPASS: test", encoding)
                self.assertEqual(self.parser.parse_logs_stream()["credentials"][0]["username"], "José")

    def test_incomplete_records_reported_without_secret(self):
        self.write("all passwords.txt", "URL: x\nPASS: sensitive\n\nURL: y\nUSER: valid\nPASS: test")
        data = self.parser.parse_logs_stream()
        self.assertEqual(len(data["credentials"]), 1)
        self.assertIn("username", data["warnings"][0]["message"])
        self.assertNotIn("sensitive", json.dumps(data["warnings"]))

    def test_separate_systems_not_overwritten_or_combined(self):
        self.write("a/system.txt", "Host: A\nOS: Windows")
        self.write("b/system.txt", "Host: B\nOS: Linux")
        data = self.parser.parse_logs_stream()
        self.assertEqual([x["fields"]["Host"] for x in data["system_records"]], ["A", "B"])
        self.assertEqual(data["system_info"], {})

    def test_single_system_legacy_view(self):
        self.write("system.txt", "Host: A")
        self.assertEqual(self.parser.parse_logs_stream()["system_info"], {"Host": "A"})

    def test_repeated_parse_does_not_duplicate(self):
        self.write("brute.txt", "test\n")
        self.parser.parse_logs_stream()
        self.assertEqual(self.parser.parse_logs_stream()["brute_passwords"], ["test"])

    def test_invalid_folder_raises(self):
        with self.assertRaises(NotADirectoryError):
            StreamLogParser(self.root / "absent").parse_logs_stream()

    def test_empty_folder_warns(self):
        self.assertIn("No supported", self.parser.parse_logs_stream()["warnings"][0]["message"])

    def test_invalid_bytes_are_visible(self):
        (self.root / "brute.txt").write_bytes(b"bad\xff")
        data = self.parser.parse_logs_stream()
        self.assertIn("\ufffd", data["brute_passwords"][0])
        self.assertEqual(len(data["warnings"]), 1)

    def test_unreadable_file_reports_error(self):
        self.write("brute.txt", "x")
        with patch.object(self.parser, "stream_read_lines", side_effect=PermissionError("denied")):
            data = self.parser.parse_logs_stream()
        self.assertEqual(data["source_files"][0]["status"], "error")
        self.assertIn("denied", data["warnings"][0]["message"])

    def test_legacy_entry_point_and_json_export(self):
        self.write("all passwords.txt", "URL: x\nUSER: a\nPASS: b")
        legacy = LogParser(self.root)
        expected = self.parser.parse_logs_stream()
        self.assertEqual(legacy.parse_logs(), expected)
        out = self.root / "results.json"
        legacy.save_results(out)
        self.assertEqual(json.loads(out.read_text()), expected)

    def test_all_line_categories(self):
        for filename in self.parser.CATEGORIES:
            self.write(filename, " One\n\nTwo \n")
        data = self.parser.parse_logs_stream()
        for category in self.parser.CATEGORIES.values():
            self.assertEqual(data[category], ["one", "two"] if category == "detected_domains" else ["One", "Two"])


if __name__ == "__main__":
    unittest.main()
