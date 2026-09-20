import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from case_processor import CaseProcessor, IntakeError


class CaseProcessorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def make_zip(self, members, name="logs.zip", compression=zipfile.ZIP_DEFLATED):
        path = self.root / name
        with zipfile.ZipFile(path, "w", compression=compression) as archive:
            for member, content in members.items():
                archive.writestr(member, content)
        return path

    def test_nested_zip_is_parsed_hashed_and_remapped(self):
        archive = self.make_zip({
            "victim/deep/Passwords.txt": "Application: Chrome\nURL: https://example.test\nUser: analyst\nPass: test-only\n",
            "victim/image.bin": b"\x00\x01",
        })
        expected_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
        data = CaseProcessor(archive, case_id="CASE-1", examiner="Examiner",
                             evidence_number="ITEM-1").process()
        self.assertEqual(len(data["credentials"]), 1)
        self.assertEqual(data["case_metadata"]["input_sha256"], expected_hash)
        self.assertEqual(data["case_metadata"]["extracted_file_count"], 2)
        self.assertEqual(data["case_metadata"]["case_id"], "CASE-1")
        files = data["source_files"]
        self.assertEqual({item["relative_path"] for item in files},
                         {"victim/deep/Passwords.txt", "victim/image.bin"})
        self.assertTrue(all(len(item["sha256"]) == 64 for item in files))
        self.assertTrue(all(item["source"].startswith("logs.zip::") for item in files))
        self.assertNotIn("stealerscope-", str(data))

    def test_directory_intake_hashes_every_file(self):
        folder = self.root / "logs"
        folder.mkdir()
        (folder / "Passwords.txt").write_text("URL: x\nUser: y\nPass: z")
        (folder / "unknown.dat").write_text("unknown")
        data = CaseProcessor(folder).process()
        self.assertIsNone(data["case_metadata"]["input_sha256"])
        self.assertEqual(len(data["source_files"]), 2)
        self.assertTrue(all("sha256" in item for item in data["source_files"]))

    def test_parent_traversal_is_rejected_without_escape(self):
        archive = self.make_zip({"../escape.txt": "bad"})
        escape = self.root.parent / "escape.txt"
        before = escape.exists()
        with self.assertRaisesRegex(IntakeError, "Unsafe archive member"):
            CaseProcessor(archive).process()
        self.assertEqual(escape.exists(), before)

    def test_absolute_and_windows_paths_are_rejected(self):
        for member in ("/absolute.txt", "C:/windows.txt", "..\\escape.txt"):
            with self.subTest(member=member):
                archive = self.make_zip({member: "bad"}, name="case.zip")
                with self.assertRaises(IntakeError):
                    CaseProcessor(archive).process()

    def test_symlink_member_is_rejected(self):
        archive = self.root / "link.zip"
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (0o120777 << 16)
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr(info, "target")
        with self.assertRaisesRegex(IntakeError, "Symbolic-link"):
            CaseProcessor(archive).process()

    def test_file_count_and_expanded_size_limits(self):
        archive = self.make_zip({"one": "1", "two": "2"})
        with self.assertRaisesRegex(IntakeError, "files; limit"):
            CaseProcessor(archive, max_files=1).process()
        with self.assertRaisesRegex(IntakeError, "expanded size"):
            CaseProcessor(archive, max_total_bytes=1).process()

    def test_member_size_and_compression_ratio_limits(self):
        archive = self.make_zip({"large.txt": "A" * 10_000})
        with self.assertRaisesRegex(IntakeError, "size limit"):
            CaseProcessor(archive, max_member_bytes=100).process()
        with self.assertRaisesRegex(IntakeError, "Compression ratio"):
            CaseProcessor(archive, max_compression_ratio=2).process()

    def test_unsupported_archive_type(self):
        path = self.root / "logs.tar"
        path.write_bytes(b"not an archive")
        with self.assertRaisesRegex(IntakeError, "Unsupported archive"):
            CaseProcessor(path).process()

    def test_missing_input(self):
        with self.assertRaises(FileNotFoundError):
            CaseProcessor(self.root / "missing.zip").process()

    def test_password_not_recorded(self):
        archive = self.make_zip({"Passwords.txt": "URL: x\nUser: y\nPass: z"})
        data = CaseProcessor(archive, password="secret").process()
        self.assertTrue(data["case_metadata"]["password_provided"])
        self.assertNotIn("secret", str(data))

    def test_archive_password_error_is_normalized(self):
        archive = self.make_zip({"Passwords.txt": "URL: x\nUser: y\nPass: z"})
        original = zipfile.ZipFile.open
        def fail(*args, **kwargs):
            raise RuntimeError("Bad password for file")
        with patch.object(zipfile.ZipFile, "open", fail):
            with self.assertRaisesRegex(IntakeError, "missing or incorrect"):
                CaseProcessor(archive).process()

    def test_7z_nested_archive_and_password(self):
        try:
            import py7zr
        except ImportError:
            self.skipTest("py7zr unavailable")
        source = self.root / "Passwords.txt"
        source.write_text("URL: x\nUSER: y\nPASS: z")
        archive = self.root / "logs.7z"
        with py7zr.SevenZipFile(archive, "w", password="test-password") as output:
            output.write(source, "deep/Passwords.txt")
        with self.assertRaisesRegex(IntakeError, "password"):
            CaseProcessor(archive).process()
        data = CaseProcessor(archive, password="test-password").process()
        self.assertEqual(len(data["credentials"]), 1)
        self.assertEqual(data["source_files"][0]["relative_path"], "deep/Passwords.txt")
        self.assertTrue(data["source_files"][0]["source"].startswith("logs.7z::"))


if __name__ == "__main__":
    unittest.main()
