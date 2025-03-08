import os
import json
import re

class StreamLogParser:
    def __init__(self, log_folder):
        """
        Initialize the parser with the log folder.
        Uses streaming methods to avoid loading entire files into memory.
        """
        self.log_folder = log_folder
        self.parsed_data = {
            "credentials": [],
            "brute_passwords": [],
            "detected_domains": [],
            "processes": [],
            "installed_software": [],
            "system_info": {}
        }

    def parse_logs_stream(self):
        """
        Walk through the log folder and stream-parse each file.
        """
        for root, _, files in os.walk(self.log_folder):
            for file in files:
                file_lower = file.lower()
                file_path = os.path.join(root, file)
                if file_lower == "all passwords.txt":
                    for cred in self.stream_parse_credentials(file_path):
                        self.parsed_data["credentials"].append(cred)
                elif file_lower == "brute.txt":
                    for line in self.stream_read_lines(file_path):
                        self.parsed_data["brute_passwords"].append(line)
                elif file_lower == "domaindetect.txt":
                    for line in self.stream_read_lines(file_path):
                        self.parsed_data["detected_domains"].append(line.lower())
                elif file_lower == "processes.txt":
                    for line in self.stream_read_lines(file_path):
                        self.parsed_data["processes"].append(line)
                elif file_lower == "software.txt":
                    for line in self.stream_read_lines(file_path):
                        self.parsed_data["installed_software"].append(line)
                elif file_lower == "system.txt":
                    self.parsed_data["system_info"] = self.stream_parse_system_info(file_path)
        return self.parsed_data

    def stream_read_lines(self, file_path):
        """
        Generator that yields non-empty, stripped lines from a file.
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        yield stripped
        except Exception as e:
            print(f"Error reading {file_path}: {e}")

    def stream_parse_credentials(self, file_path):
        """
        Generator to parse credentials from a file.
        A credential block is separated by a blank line.
        Expected lines:
          - SOFT: <software info>  [optional]
          - URL: <url>
          - USER: <username>
          - PASS: <password>
        """
        def parse_block(block):
            cred = {}
            for line in block:
                if line.startswith("SOFT:"):
                    cred["soft"] = line[len("SOFT:"):].strip()
                elif line.startswith("URL:"):
                    cred["url"] = line[len("URL:"):].strip()
                elif line.startswith("USER:"):
                    cred["username"] = line[len("USER:"):].strip()
                elif line.startswith("PASS:"):
                    cred["password"] = line[len("PASS:"):].strip()
            return cred

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                block = []
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        block.append(stripped)
                    else:
                        if block:
                            cred = parse_block(block)
                            # Yield only if mandatory fields are present.
                            if "url" in cred and "username" in cred and "password" in cred:
                                yield cred
                            block = []
                # Process the last block if the file doesn't end with a blank line.
                if block:
                    cred = parse_block(block)
                    if "url" in cred and "username" in cred and "password" in cred:
                        yield cred
        except Exception as e:
            print(f"Error parsing credentials in {file_path}: {e}")

    def stream_parse_system_info(self, file_path):
        """
        Parses system info file where each line is in 'Key: Value' format.
        """
        info = {}
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            key, value = parts
                            info[key.strip()] = value.strip()
            return info
        except Exception as e:
            print(f"Error parsing system info in {file_path}: {e}")
            return info

    def save_results(self, output_file="parsed_results.json"):
        """
        Saves the parsed data to a JSON file.
        """
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(self.parsed_data, f, indent=4)
            return output_file
        except Exception as e:
            print(f"Error saving results to {output_file}: {e}")
            return None

# Example usage:
if __name__ == "__main__":
    parser = StreamLogParser("logs/")
    data = parser.parse_logs_stream()
    print("Parsed data summary:")
    print(f"Credentials: {len(data['credentials'])}")
    print(f"Brute passwords: {len(data['brute_passwords'])}")
    print(f"Detected domains: {len(data['detected_domains'])}")
    print(f"Processes: {len(data['processes'])}")
    print(f"Installed software: {len(data['installed_software'])}")
    print(f"System info: {data['system_info']}")
