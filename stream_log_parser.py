"""Offline, line-oriented parsing of infostealer logs for analysis."""
import codecs
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
    LABELS = {"url": "url", "user": "username", "username": "username",
              "login": "username", "pass": "password", "password": "password",
              "soft": "soft", "browser": "soft"}

    def __init__(self, log_folder):
        self.log_folder = os.fspath(log_folder)
        self._reset()

    def _reset(self):
        self.parsed_data = {key: [] for key in
                            ("credentials", "brute_passwords", "detected_domains",
                             "processes", "installed_software", "system_records",
                             "warnings", "source_files")}
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
        if prefix.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
            encoding = "utf-32"
        elif prefix.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            encoding = "utf-16"
        else:
            encoding = "utf-8-sig"
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
        def walk_error(error):
            self._warning(error.filename or self.log_folder, str(error))
        for root, directories, files in os.walk(self.log_folder, onerror=walk_error):
            directories.sort()
            for filename in sorted(files):
                name = filename.lower()
                if name not in self.CATEGORIES and name not in ("all passwords.txt", "passwords.txt", "system.txt"):
                    continue
                path = os.path.join(root, filename)
                if os.path.islink(path):
                    self._warning(path, "Skipped symbolic link.")
                    continue
                source = {"source": path, "status": "parsed"}
                try:
                    if name in ("all passwords.txt", "passwords.txt"):
                        self.parsed_data["credentials"].extend(self.stream_parse_credentials(path))
                    elif name == "system.txt":
                        info = self.stream_parse_system_info(path)
                        self.parsed_data["system_records"].append({"source": path, "fields": info})
                    else:
                        values = self.stream_read_lines(path)
                        if name == "domaindetect.txt":
                            values = (value.lower() for value in values)
                        self.parsed_data[self.CATEGORIES[name]].extend(values)
                except OSError as error:
                    source["status"] = "error"
                    self._warning(path, str(error))
                self.parsed_data["source_files"].append(source)
        records = self.parsed_data["system_records"]
        # Preserve the legacy single-system view only when it is unambiguous.
        if len(records) == 1:
            self.parsed_data["system_info"] = dict(records[0]["fields"])
        if not self.parsed_data["source_files"]:
            self._warning(self.log_folder, "No supported log files found.")
        return self.parsed_data

    def stream_read_lines(self, file_path):
        for _, line in self._lines(file_path):
            if line.strip():
                yield line.strip()

    def stream_parse_credentials(self, file_path):
        record = {}
        start_line = None
        required = {"url", "username", "password"}

        def finish():
            if required.issubset(record):
                return dict(record, source=os.fspath(file_path), source_line=start_line)
            if record:
                self._warning(file_path, "Incomplete credential record; missing " +
                              ", ".join(sorted(required - record.keys())), start_line)
            return None

        for number, line in self._lines(file_path):
            if not line.strip() or re.fullmatch(r"\s*[-=]{3,}\s*", line):
                result = finish()
                if result:
                    yield result
                record, start_line = {}, None
                continue
            match = re.match(r"^\s*([A-Za-z]+)\s*:(.*)$", line)
            if not match:
                continue
            key = self.LABELS.get(match[1].lower())
            if key is None:
                continue
            # Repeated fields begin another record even without a blank separator.
            if key in record or (key == "soft" and required.issubset(record)):
                result = finish()
                if result:
                    yield result
                record, start_line = {}, None
            if start_line is None:
                start_line = number
            value = match[2]
            # Remove one conventional delimiter space, preserving password whitespace.
            if value.startswith(" "):
                value = value[1:]
            record[key] = value if key == "password" else value.strip()
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
