"""Offline, line-oriented parsing of infostealer logs for analysis."""
import csv
import stat
from collections import Counter
from log_detection import detect_file, family_assessment, text_encoding, LABELS
import json
import os
import re


class StreamLogParser:
    CATEGORIES = {
        "brute.txt": "brute_passwords",
        "domaindetect.txt": "detected_domains",
        "processes.txt": "processes",
        "software.txt": "installed_software",
    }
    LABELS = LABELS

    def __init__(self, log_folder):
        self.log_folder = os.fspath(log_folder)
        self._reset()

    def _reset(self):
        self.parsed_data = {key: [] for key in
                            ("credentials", "brute_passwords", "detected_domains",
                             "processes", "installed_software", "system_records",
                             "warnings", "source_files", "cookies")}
        self.parsed_data["system_info"] = {}

    def _warning(self, source, message, line=None):
        warning = {"source": os.fspath(source), "message": message}
        if line is not None:
            warning["line"] = line
        self.parsed_data["warnings"].append(warning)

    def _lines(self, file_path):
        # BOM detection avoids silently stripping UTF-16 bytes or UTF-8 BOMs.
        with open(file_path, "rb") as raw:
            prefix = raw.read(4)
        encoding = text_encoding(prefix)
        with open(file_path, encoding=encoding, errors="replace") as stream:
            warned = False
            for number, line in enumerate(stream, 1):
                if "\ufffd" in line and not warned:
                    self._warning(file_path, "Invalid text encoding; replacement characters present.", number)
                    warned = True
                yield number, line.rstrip("\r\n")

    def parse_logs_stream(self):
        self._reset()
        if not os.path.isdir(self.log_folder):
            raise NotADirectoryError(f"Log folder is not a directory: {self.log_folder}")
        inventory = self.parsed_data["source_files"]
        enumeration_errors = []
        def walk_error(error):
            enumeration_errors.append(str(error))
            self._warning(error.filename or self.log_folder, str(error))
        for root, directories, files in os.walk(self.log_folder, onerror=walk_error):
            directories.sort()
            for directory in directories[:]:
                path = os.path.join(root, directory)
                if os.path.islink(path):
                    directories.remove(directory)
                    inventory.append({"source": path, "entry_type": "directory", "status": "skipped",
                                      "reason": "Symbolic link directory not followed.", "records_parsed": 0})
            for filename in sorted(files):
                path = os.path.join(root, filename)
                source = {"source": path, "entry_type": "file", "status": "unsupported", "records_parsed": 0}
                inventory.append(source)
                warnings_before = len(self.parsed_data["warnings"])
                try:
                    mode = os.lstat(path).st_mode
                    if not stat.S_ISREG(mode):
                        source.update(status="skipped", reason="Symbolic link or non-regular file not opened.")
                        continue
                    detection = detect_file(path)
                    source["detection"] = detection
                    format_name = detection["format"]
                    if format_name in ("unknown", "ambiguous", "binary"):
                        source["reason"] = detection.get("reason", "No supported parser.")
                        continue
                    if format_name == "credential_blocks":
                        records, target = self.stream_parse_credentials(path), "credentials"
                    elif format_name == "credential_table":
                        records, target = self.stream_parse_credential_table(path, detection["delimiter"]), "credentials"
                    elif format_name == "netscape_cookies":
                        records, target = self.stream_parse_cookies(path), "cookies"
                    elif format_name == "system_key_values":
                        info = self.stream_parse_system_info(path)
                        records = [{"source": path, "fields": info}] if info else []
                        target = "system_records"
                    else:
                        target = self.CATEGORIES[filename.lower()]
                        records = self.stream_read_lines(path)
                        if target == "detected_domains":
                            records = (value.lower() for value in records)
                    for record in records:
                        self.parsed_data[target].append(record)
                        source["records_parsed"] += 1
                    if not source["records_parsed"]:
                        self._warning(path, "Recognized format or filename but no records were parsed.")
                    source["status"] = "partial" if len(self.parsed_data["warnings"]) > warnings_before else "parsed"
                except (OSError, csv.Error, UnicodeError) as error:
                    source["status"] = "failed"
                    source["reason"] = str(error)
                    self._warning(path, str(error))
                finally:
                    source["warning_count"] = len(self.parsed_data["warnings"]) - warnings_before
        records = self.parsed_data["system_records"]
        if len(records) == 1:
            self.parsed_data["system_info"] = dict(records[0]["fields"])
        counts = Counter(item["status"] for item in inventory if item["entry_type"] == "file")
        self.parsed_data["import_summary"] = {
            "files_enumerated": sum(counts.values()),
            **{status: counts[status] for status in ("parsed", "partial", "unsupported", "skipped", "failed")},
            "directories_skipped": sum(item["entry_type"] == "directory" for item in inventory),
            "enumeration_complete": not enumeration_errors,
            "enumeration_errors": enumeration_errors,
            "detection_sample_limit_bytes": 65536,
        }
        claims = [e for item in inventory for e in item.get("detection", {}).get("family_assessment", {}).get("evidence", [])]
        self.parsed_data["family_assessment"] = family_assessment(claims)
        if not counts["parsed"] and not counts["partial"]:
            self._warning(self.log_folder, "No supported log files found or successfully parsed.")
        return self.parsed_data

    def stream_parse_credential_table(self, file_path, delimiter):
        # Preserve original newlines inside quoted fields. _lines supplies decoding
        # warnings while csv.reader handles quoted delimiters and multiline records.
        reader = csv.reader((line + "\n" for _, line in self._lines(file_path)), delimiter=delimiter, strict=True)
        header = next(reader, [])
        fields = [self.LABELS.get(value.strip().lower()) for value in header]
        required = {"username", "password"}
        if not required.issubset(fields) or any(fields.count(key) != 1 for key in required):
            self._warning(file_path, "Missing or duplicate credential table columns.", 1)
            return
        while True:
            start_line = reader.line_num + 1
            try:
                row = next(reader)
            except StopIteration:
                return
            if not row:
                continue
            if len(row) != len(header):
                self._warning(file_path, "Credential table row has an unexpected column count.", start_line)
                continue
            record = {key: value for key, value in zip(fields, row) if key}
            yield dict(record, source=os.fspath(file_path), source_line=start_line)

    def stream_parse_cookies(self, file_path):
        for number, line in self._lines(file_path):
            http_only = line.startswith("#HttpOnly_")
            if http_only:
                line = line[len("#HttpOnly_"):]
            elif not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 7 or parts[1] not in ("TRUE", "FALSE") or parts[3] not in ("TRUE", "FALSE") or not parts[4].isdigit():
                self._warning(file_path, "Malformed Netscape cookie record.", number)
                continue
            yield {"domain": parts[0], "include_subdomains": parts[1] == "TRUE", "path": parts[2],
                   "secure": parts[3] == "TRUE", "expires_epoch": parts[4], "name": parts[5],
                   "value": parts[6], "http_only": http_only, "source": os.fspath(file_path), "source_line": number}

    def stream_read_lines(self, file_path):
        for _, line in self._lines(file_path):
            if line.strip():
                yield line.strip()

    def stream_parse_credentials(self, file_path):
        record = {}
        start_line = None
        pending_soft = None
        required = {"username", "password"}

        def finish():
            if required.issubset(record):
                return dict(record, source=os.fspath(file_path), source_line=start_line)
            if record:
                self._warning(file_path, "Incomplete credential record; missing " +
                              ", ".join(sorted(required - record.keys())), start_line)
            return None

        for number, line in self._lines(file_path):
            if not line.strip() or re.fullmatch(r"\s*[-=]{3,}\s*", line):
                if pending_soft:
                    record["soft"] = pending_soft[0]
                    pending_soft = None
                result = finish()
                if result:
                    yield result
                record, start_line = {}, None
                continue
            match = re.match(r"^\s*([^:]{1,40})\s*:(.*)$", line)
            key = self.LABELS.get(match[1].strip().lower()) if match else None
            if pending_soft:
                if key in ("url", "username"):
                    result = finish()
                    if result:
                        yield result
                    record = {"soft": pending_soft[0]}
                    start_line = pending_soft[1]
                else:
                    record["soft"] = pending_soft[0]
                pending_soft = None
            if key is None:
                # Some exports store a password over multiple physical lines. Once
                # PASS/PASSWORD has started, preserve every non-field line verbatim
                # until a blank line, separator, or recognized next field.
                if "password" in record:
                    record["password"] += "\n" + line
                continue
            value = match[2]
            if value.startswith(" "):
                value = value[1:]
            value = value if key == "password" else value.strip()
            # Application metadata occurs both after a credential and before the
            # next one. Defer it one line so the following field resolves ownership.
            if key == "soft" and required.issubset(record) and "soft" not in record:
                pending_soft = (value, number)
                continue
            if key in record or (required.issubset(record) and key in ("url", "username")):
                result = finish()
                if result:
                    yield result
                record, start_line = {}, None
            if start_line is None:
                start_line = number
            record[key] = value
        if pending_soft:
            record["soft"] = pending_soft[0]
        result = finish()
        if result:
            yield result

    def stream_parse_system_info(self, file_path):
        info = {}
        for _, line in self._lines(file_path):
            if ":" in line:
                key, value = line.split(":", 1)
                if key.strip():
                    info[key.strip()] = value.strip()
        return info

    def save_results(self, output_file="parsed_results.json"):
        with open(output_file, "w", encoding="utf-8") as stream:
            json.dump(self.parsed_data, stream, indent=4, ensure_ascii=False)
        return output_file
