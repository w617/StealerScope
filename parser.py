"""Compatibility entry point using the shared streaming parser."""
from stream_log_parser import StreamLogParser


class LogParser(StreamLogParser):
    def parse_logs(self):
        return self.parse_logs_stream()
