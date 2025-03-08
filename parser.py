import os
import json
import re

class LogParser:
    def __init__(self, log_folder):
        """Initialize parser with log folder path."""
        self.log_folder = log_folder
        self.parsed_data = {
            "credentials": [],
            "brute_passwords": [],
            "detected_domains": [],
            "processes": [],
            "installed_software": [],
            "system_info": {}
        }

    def parse_logs(self):
        """Parses all logs in the specified folder."""
        if not os.path.exists(self.log_folder):
            raise FileNotFoundError(f"Log folder '{self.log_folder}' not found.")

        for root, _, files in os.walk(self.log_folder):
            for file in files:
                file_path = os.path.join(root, file)
                if file.lower() == "all passwords.txt":
                    self._parse_credentials(file_path)
                elif file.lower() == "brute.txt":
                    self._parse_brute_passwords(file_path)
                elif file.lower() == "domaindetect.txt":
                    self._parse_detected_domains(file_path)
                elif file.lower() == "processes.txt":
                    self._parse_processes(file_path)
                elif file.lower() == "software.txt":
                    self._parse_installed_software(file_path)
                elif file.lower() == "system.txt":
                    self._parse_system_info(file_path)

        return self.parsed_data

    def _parse_credentials(self, file_path):
        """Extracts credentials from All Passwords.txt"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            cred_pattern = re.findall(r"URL:\s*(.*?)\nUSER:\s*(.*?)\nPASS:\s*(.*?)\n", content, re.MULTILINE)
            for match in cred_pattern:
                self.parsed_data["credentials"].append({
                    "source": file_path,
                    "url": match[0].strip(),
                    "username": match[1].strip(),
                    "password": match[2].strip()
                })
        except Exception as e:
            print(f"❌ Error parsing {file_path}: {e}")

    def _parse_brute_passwords(self, file_path):
        """Extracts passwords from Brute.txt"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
            self.parsed_data["brute_passwords"].extend(lines)
        except Exception as e:
            print(f"❌ Error parsing {file_path}: {e}")

    def _parse_detected_domains(self, file_path):
        """Extracts detected domains from DomainDetect.txt"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [line.strip().lower() for line in f.readlines() if line.strip()]
            self.parsed_data["detected_domains"].extend(lines)
        except Exception as e:
            print(f"❌ Error parsing {file_path}: {e}")

    def _parse_processes(self, file_path):
        """Extracts running processes from Processes.txt"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
            self.parsed_data["processes"].extend(lines)
        except Exception as e:
            print(f"❌ Error parsing {file_path}: {e}")

    def _parse_installed_software(self, file_path):
        """Extracts installed software from Software.txt"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
            self.parsed_data["installed_software"].extend(lines)
        except Exception as e:
            print(f"❌ Error parsing {file_path}: {e}")

    def _parse_system_info(self, file_path):
        """Extracts system information from System.txt"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            system_info = {}
            for line in lines:
                key_value = re.match(r"^(.*?):\s*(.*?)$", line.strip())
                if key_value:
                    key, value = key_value.groups()
                    system_info[key.strip()] = value.strip()
            self.parsed_data["system_info"] = system_info
        except Exception as e:
            print(f"❌ Error parsing {file_path}: {e}")

    def save_results(self, output_file="parsed_results.json"):
        """Saves parsed results to a JSON file."""
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(self.parsed_data, f, indent=4)
            return output_file
        except Exception as e:
            print(f"❌ Error saving results to {output_file}: {e}")
            return None
