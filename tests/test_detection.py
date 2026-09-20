"""Synthetic format fixtures; these do not validate real malware-family attribution."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from log_detection import SAMPLE_BYTES, detect_file
from stream_log_parser import StreamLogParser


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def parse(self):
        return StreamLogParser(self.root).parse_logs_stream()

    def test_renamed_credentials_detected_by_content(self):
        self.write("random.bin", "URL: https://example.test\nLOGIN: alice\nPASSWORD: secret")
        data = self.parse()
        self.assertEqual(len(data["credentials"]), 1)
        detection = data["source_files"][0]["detection"]
        self.assertEqual(detection["format"], "credential_blocks")
        self.assertEqual(detection["confidence"], "high")
        self.assertEqual(data["family_assessment"]["status"], "unknown")
        self.assertNotIn("secret", json.dumps(detection))

    def test_filename_hint_is_low_confidence_not_family(self):
        self.write("passwords.txt", "random text")
        data = self.parse()
        self.assertEqual(data["source_files"][0]["detection"]["confidence"], "low")
        self.assertEqual(data["source_files"][0]["status"], "partial")
        self.assertEqual(data["family_assessment"]["status"], "unknown")

    def test_csv_quotes_and_multiline(self):
        self.write("renamed.data", 'URL,Username,Password\nhttps://example.test,alice,"a,b"\nhttps://example.test,bob,"first\nsecond"\n')
        data = self.parse()
        self.assertEqual([r["password"] for r in data["credentials"]], ["a,b", "first\nsecond"])
        self.assertEqual([r["source_line"] for r in data["credentials"]], [2, 3])
        self.assertEqual(data["source_files"][0]["records_parsed"], 2)

    def test_tsv_and_semicolon_tables(self):
        for delimiter in ("\t", ";"):
            with self.subTest(delimiter=delimiter):
                self.write("table", delimiter.join(("url", "login", "pass")) + "\n" + delimiter.join(("site", "user", "test")))
                self.assertEqual(self.parse()["credentials"][0]["password"], "test")

    def test_bad_table_row_is_accounted_as_partial(self):
        self.write("table.csv", "url,user,pass\nx,a,b\ny,c\n")
        data = self.parse()
        self.assertEqual(len(data["credentials"]), 1)
        self.assertEqual(data["import_summary"]["partial"], 1)
        self.assertEqual(data["warnings"][0]["line"], 3)

    def test_malformed_csv_fails_without_losing_prior_count(self):
        self.write("table.csv", 'url,user,pass\nx,a,b\ny,c,"unterminated\n')
        data = self.parse()
        self.assertEqual(data["source_files"][0]["status"], "failed")
        self.assertEqual(data["source_files"][0]["records_parsed"], 1)

    def test_cookie_fields_and_invalid_row(self):
        self.write("anything", "# Netscape HTTP Cookie File\n#HttpOnly_.example.test\tTRUE\t/\tTRUE\t12345\tsession\ttest-value\nbad row\n")
        data = self.parse()
        cookie = data["cookies"][0]
        self.assertTrue(cookie["http_only"])
        self.assertTrue(cookie["secure"])
        self.assertEqual(cookie["source_line"], 2)
        self.assertEqual(data["import_summary"]["partial"], 1)

    def test_renamed_system_file(self):
        self.write("host-details.log", "Computer Name: workstation\nOperating System: Windows\n")
        data = self.parse()
        self.assertEqual(data["system_records"][0]["fields"]["Computer Name"], "workstation")
        self.assertEqual(data["source_files"][0]["detection"]["confidence"], "medium")

    def test_family_label_is_only_unverified_claim(self):
        self.write("sample", "Stealer: Lumma\nURL: x\nUSER: y\nPASS: z\n")
        assessment = self.parse()["family_assessment"]
        self.assertEqual(assessment["status"], "unverified")
        self.assertIsNone(assessment["family"])
        self.assertEqual(assessment["candidates"], ["lumma"])
        self.assertEqual(assessment["confidence"], "low")
        self.assertEqual(assessment["evidence"][0]["line"], 1)

    def test_conflicting_claims_are_ambiguous(self):
        self.write("one", "Family: RedLine\n")
        self.write("two", "Family: Vidar\n")
        data = self.parse()
        self.assertEqual(data["family_assessment"]["status"], "ambiguous")
        self.assertIsNone(data["family_assessment"]["family"])

    def test_family_name_in_path_password_or_url_not_a_signature(self):
        self.write("RedLine/passwords.txt", "URL: https://lumma.test\nUSER: vidar\nPASS: Family: RedLine\n")
        self.assertEqual(self.parse()["family_assessment"]["status"], "unknown")

    def test_inventory_accounts_for_every_file(self):
        self.write("good", "url: x\nuser: a\npass: b")
        self.write("unknown", "unrecognized")
        self.write("empty", "")
        (self.root / "image.png").write_bytes(b"\x89PNG\x00\x00")
        self.write("broken/passwords.txt", "URL: x\n")
        data = self.parse()
        summary = data["import_summary"]
        self.assertEqual(summary["files_enumerated"], 5)
        self.assertEqual(summary["parsed"], 1)
        self.assertEqual(summary["unsupported"], 3)
        self.assertEqual(summary["partial"], 1)
        self.assertEqual(sum(summary[k] for k in ("parsed", "partial", "unsupported", "skipped", "failed")), 5)

    def test_symbolic_links_are_accounted_without_following(self):
        target = self.write("target", "unknown")
        try:
            (self.root / "link").symlink_to(target)
            (self.root / "loop").symlink_to(self.root, target_is_directory=True)
        except OSError:
            self.skipTest("Symbolic links unavailable")
        summary = self.parse()["import_summary"]
        self.assertEqual(summary["files_enumerated"], 2)
        self.assertEqual(summary["skipped"], 1)
        self.assertEqual(summary["directories_skipped"], 1)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO unavailable")
    def test_special_file_not_opened(self):
        os.mkfifo(self.root / "pipe")
        self.assertEqual(self.parse()["import_summary"]["skipped"], 1)

    def test_bounded_detection_documents_truncation(self):
        path = self.write("large", "x" * (SAMPLE_BYTES + 100) + "\nFamily: Lumma")
        detection = detect_file(path)
        self.assertTrue(detection["sample_truncated"])
        self.assertEqual(detection["sample_bytes"], SAMPLE_BYTES)
        self.assertEqual(detection["family_assessment"]["status"], "unknown")

    def test_ambiguous_format_is_not_forced(self):
        self.write("mixed", "URL: x\nUSER: a\nPASS: b\n.example.test\tTRUE\t/\tFALSE\t0\tname\tvalue\n")
        data = self.parse()
        self.assertEqual(data["source_files"][0]["detection"]["format"], "ambiguous")
        self.assertEqual(data["import_summary"]["unsupported"], 1)
        self.assertEqual(data["credentials"], [])

    def test_directory_read_failure_marks_enumeration_incomplete(self):
        def failed_walk(root, onerror):
            onerror(PermissionError("directory inaccessible"))
            return iter([])
        with patch("stream_log_parser.os.walk", side_effect=failed_walk):
            data = self.parse()
        self.assertFalse(data["import_summary"]["enumeration_complete"])
        self.assertTrue(data["import_summary"]["enumeration_errors"])

    def test_file_read_failure_is_counted(self):
        self.write("test", "text")
        with patch("stream_log_parser.detect_file", side_effect=PermissionError("denied")):
            data = self.parse()
        self.assertEqual(data["import_summary"]["failed"], 1)

    def test_bom_content_detection(self):
        for encoding in ("utf-16", "utf-32", "utf-8-sig"):
            with self.subTest(encoding=encoding):
                path = self.root / "renamed"
                path.write_text("URL: x\nUSER: José\nPASS: test", encoding=encoding)
                self.assertEqual(self.parse()["credentials"][0]["username"], "José")

    def test_bare_colon_credentials_are_not_guessed(self):
        self.write("dump.txt", "https://example.test:user:password:with:colons")
        self.assertEqual(self.parse()["import_summary"]["unsupported"], 1)


if __name__ == "__main__":
    unittest.main()
