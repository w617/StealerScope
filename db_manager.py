import sqlite3

class DBManager:
    def __init__(self, db_path="logs_data.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        # Credentials table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT,
                url TEXT,
                username TEXT,
                password TEXT
            )
        """)
        # Brute passwords table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS brute_passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                password TEXT
            )
        """)
        # Detected domains table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detected_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT
            )
        """)
        # Processes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS processes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_name TEXT
            )
        """)
        # Installed software table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS installed_software (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                software_name TEXT
            )
        """)
        # System info table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT,
                value TEXT
            )
        """)
        self.conn.commit()

    def insert_parsed_data(self, parsed_data):
        cursor = self.conn.cursor()
        # Insert credentials
        for cred in parsed_data.get("credentials", []):
            cursor.execute("""
                INSERT INTO credentials (source, url, username, password)
                VALUES (?, ?, ?, ?)
            """, (cred.get("source"), cred.get("url"), cred.get("username"), cred.get("password")))
        # Insert brute passwords
        for pwd in parsed_data.get("brute_passwords", []):
            cursor.execute("INSERT INTO brute_passwords (password) VALUES (?)", (pwd,))
        # Insert detected domains
        for domain in parsed_data.get("detected_domains", []):
            cursor.execute("INSERT INTO detected_domains (domain) VALUES (?)", (domain,))
        # Insert processes
        for proc in parsed_data.get("processes", []):
            cursor.execute("INSERT INTO processes (process_name) VALUES (?)", (proc,))
        # Insert installed software
        for sw in parsed_data.get("installed_software", []):
            cursor.execute("INSERT INTO installed_software (software_name) VALUES (?)", (sw,))
        # Insert system info (as key-value pairs)
        system_info = parsed_data.get("system_info", {})
        for key, value in system_info.items():
            cursor.execute("INSERT INTO system_info (key, value) VALUES (?, ?)", (key, value))
        self.conn.commit()

    def close(self):
        self.conn.close()

# Example usage:
if __name__ == "__main__":
    from stream_log_parser import StreamLogParser
    parser = StreamLogParser("logs/")
    data = parser.parse_logs_stream()
    db = DBManager()
    db.insert_parsed_data(data)
    print("Data inserted into the database.")
    db.close()
