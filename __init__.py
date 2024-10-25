#!/usr/bin/env python3

import argparse
import io
import re
import sys
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from itertools import groupby
from typing import Dict, List, Pattern, Tuple

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')











class LogAnalyzer:




    def __init__(self, show_examples=False):
        self.show_examples = show_examples
        self.log_pattern = re.compile(
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # Timestamp
            r'(\S+)\s+'                                     # Hostname
            r'(\S+)\[(\d+)\]:\s+'                          # Service[PID]
            r'\[(\w+)\]\s+'                                # Log level
            r'(.+)$'                                       # Message
        )

        self.variable_patterns = [
            # System identifiers
            (re.compile(r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b'), '<MONTH>'),
            (re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?'), '<TIMESTAMP>'),
            (re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I), '<UUID>'),
            # Network patterns
            (re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'), '<IP>'),
            (re.compile(r'(?::\d+)\b'), '<PORT>'),
            (re.compile(r'\b([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b'), '<MAC>'),
            # System resources
            (re.compile(r'\b\d+[KMGTPk]?[Bb]\b'), '<SIZE>'),
            (re.compile(r'\b\d+%\b'), '<PERCENTAGE>'),
            (re.compile(r'\b\d+ms\b'), '<LATENCY>'),
            # File system
            (re.compile(r'/[/\w.-]+'), '<PATH>'),
            (re.compile(r'\b\w+\.[A-Za-z0-9]+\b'), '<FILE>'),
            # Generic numbers (should be last to avoid overriding specific patterns)
            (re.compile(r'\b\d+\b'), '<NUMBER>')
        ]

        # Known error patterns for troubleshooting
        self.error_patterns = {
            'connection': re.compile(r'(?i)(connection|timeout|refused|unreachable)'),
            'permission': re.compile(r'(?i)(permission denied|access denied|unauthorized)'),
            'resource': re.compile(r'(?i)(out of memory|disk full|no space|resource unavailable)'),
            'service': re.compile(r'(?i)(failed to start|stopped|terminated|crash)'),
            'config': re.compile(r'(?i)(invalid config|configuration error|missing parameter)'),
            'dependency': re.compile(r'(?i)(missing dependency|required service|not found)'),
        }

        self.date_groups = defaultdict(lambda: defaultdict(list))
        self.pattern_counts = defaultdict(lambda: defaultdict(int))
        self.error_analysis = defaultdict(lambda: defaultdict(int))
        self.service_status = defaultdict(lambda: {'starts': 0, 'stops': 0, 'failures': 0})
        self.multiline_buffer = []
        self.current_entry = None

    def analyze_error_pattern(self, message: str) -> List[str]:
        """Identify known error patterns in the message."""
        found_patterns = []
        for error_type, pattern in self.error_patterns.items():
            if pattern.search(message):
                found_patterns.append(error_type)
        return found_patterns

    def analyze_service_status(self, service: str, message: str) -> None:
        """Track service status changes."""
        if re.search(r'(?i)starting|initialized|launched', message):
            self.service_status[service]['starts'] += 1
        elif re.search(r'(?i)stopped|terminated|shutdown', message):
            self.service_status[service]['stops'] += 1
        elif re.search(r'(?i)failed|error|crashed', message):
            self.service_status[service]['failures'] += 1

    def get_severity_score(self, level: str, message: str) -> int:
        """Calculate severity score based on log level and content."""
        base_scores = {
            'EMERGENCY': 5,
            'ALERT': 4,
            'CRITICAL': 4,
            'ERROR': 3,
            'WARNING': 2,
            'NOTICE': 1,
            'INFO': 0,
            'DEBUG': 0
        }

        score = base_scores.get(level.upper(), 0)

        # Increase score based on error patterns
        if any(pattern.search(message) for pattern in self.error_patterns.values()):
            score += 1

        return score

    def parse_timestamp(self, timestamp_str: str) -> datetime:
        try:
            current_year = datetime.now().year
            timestamp_with_year = f"{timestamp_str} {current_year}"
            return datetime.strptime(timestamp_with_year, "%b %d %H:%M:%S %Y")
        except ValueError as e:
            print(f"Error parsing timestamp: {timestamp_str}")
            return None

    def get_date_key(self, timestamp: str) -> str:
        dt = self.parse_timestamp(timestamp)
        return dt.strftime("%Y-%m-%d") if dt else "unknown"

    def normalize_message(self, message: str) -> str:
        normalized = message
        for pattern, placeholder in self.variable_patterns:
            normalized = pattern.sub(placeholder, normalized)
        return normalized

    def get_pattern_key(self, entry: Dict) -> str:
        if not entry:
            return None

        pattern = f"{entry['hostname']} {entry['service']}[<NUMBER>]: [{entry['level']}] "
        pattern += self.normalize_message(entry['message'])
        return pattern

    def parse_log_line(self, line: str) -> Dict:
        match = self.log_pattern.match(line)
        if not match:
            return None

        timestamp, hostname, service, pid, level, message = match.groups()
        return {
            'timestamp': timestamp,
            'hostname': hostname,
            'service': service,
            'pid': pid,
            'level': level,
            'message': message,
            'original': line.strip()
        }



    def process_log_file(self, file_path: str, start_time: datetime = None, end_time: datetime = None, duration_minutes: int = None) -> None:
        if duration_minutes and start_time:
            end_time = start_time + timedelta(minutes=duration_minutes)

        try:
            with open(file_path, 'r') as file:
                for line in file:
                    line = line.strip()
                    if not line:
                        continue

                    parsed = self.parse_log_line(line)
                    if parsed:
                        entry_time = self.parse_timestamp(parsed['timestamp'])

                        # Skip log lines outside the specified time range
                        if start_time and entry_time < start_time:
                            continue
                        if end_time and entry_time > end_time:
                            break

                        if self.multiline_buffer:
                            self.process_multiline_entry()
                        self.current_entry = parsed
                        self.multiline_buffer = [line]
                    else:
                        if self.current_entry:
                            self.multiline_buffer.append(line)

                if self.multiline_buffer:
                    self.process_multiline_entry()

        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found.")
            sys.exit(1)
        except Exception as e:
            print(f"Error processing file: {str(e)}")
            sys.exit(1)


    def process_multiline_entry(self) -> None:
        if not self.current_entry:
            return

        date_key = self.get_date_key(self.current_entry['timestamp'])
        full_message = '\n'.join(self.multiline_buffer)
        pattern_key = self.get_pattern_key(self.current_entry)

        self.date_groups[date_key][pattern_key].append({
            'timestamp': self.current_entry['timestamp'],
            'level': self.current_entry['level'],
            'original': full_message
        })
        self.pattern_counts[date_key][pattern_key] += 1

    def generate_report(self) -> None:
        """Generate a markdown-formatted analysis report."""
        print("# JournalCtl Log Analysis Report\n")

        sorted_dates = sorted(self.date_groups.keys())

        for date in sorted_dates:
            print(f"## {date}\n")

            patterns = self.pattern_counts[date]
            total_entries = sum(patterns.values())

            print(f"**Total log entries**: {total_entries}\n")

            # Critical Issues Section
            print("### 🚨 Critical Issues\n")
            critical_patterns = []
            for pattern, entries in self.date_groups[date].items():
                for entry in entries:
                    severity = self.get_severity_score(entry['level'], entry['original'])
                    if severity >= 3:  # Critical threshold
                        critical_patterns.append((pattern, entry, severity))

            if critical_patterns:
                critical_patterns.sort(key=lambda x: x[2], reverse=True)
                for pattern, entry, severity in critical_patterns[:5]:  # Top 5 critical issues
                    print(f"- **Severity {severity}** | `{entry['timestamp']}` | {pattern}\n")
            else:
                print("*No critical issues detected*\n")

            # Service Status Summary
            print("### 📊 Service Status\n")
            print("| Service | Starts | Stops | Failures |")
            print("|---------|---------|--------|-----------|")
            for service, stats in self.service_status.items():
                print(f"| {service} | {stats['starts']} | {stats['stops']} | {stats['failures']} |")
            print()

            # Pattern Groups
            print("### 📋 Log Patterns\n")
            pattern_items = list(patterns.items())
            pattern_items.sort(key=lambda x: (-x[1], x[0]))

            for count, group in groupby(pattern_items, key=lambda x: x[1]):
                group_patterns = list(group)
                percentage = (count / total_entries) * 100

                print(f"#### Frequency: {count} ({percentage:.1f}%)\n")

                for pattern, _ in group_patterns:
                    print("```")
                    print(pattern)
                    print("```\n")

                    if self.show_examples:
                        print("<details>")
                        print("<summary>Example Entries</summary>\n")
                        for entry in self.date_groups[date][pattern][:3]:
                            print("```")
                            print(f"[{entry['timestamp']}] [{entry['level']}]")
                            print(entry['original'])
                            print("```")
                        print("</details>\n")

            # Log Level Distribution
            print("### 📈 Log Level Distribution\n")
            level_stats = defaultdict(int)
            for pattern in self.date_groups[date]:
                for entry in self.date_groups[date][pattern]:
                    level_stats[entry['level']] += 1

            print("| Level | Count | Percentage |")
            print("|-------|-------|------------|")
            for level, count in sorted(level_stats.items()):
                percentage = (count / total_entries) * 100
                print(f"| {level} | {count} | {percentage:.1f}% |")
            print()

            # Error Type Analysis
            error_types = defaultdict(int)
            for pattern in self.date_groups[date]:
                for entry in self.date_groups[date][pattern]:
                    for error_type in self.analyze_error_pattern(entry['original']):
                        error_types[error_type] += 1

            if error_types:
                print("### ⚠️ Error Type Analysis\n")
                print("| Error Type | Occurrences |")
                print("|------------|-------------|")
                for error_type, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True):
                    print(f"| {error_type.title()} | {count} |")
                print()



def main():
    parser = argparse.ArgumentParser(description='Analyze JournalCtl log files for patterns and troubleshooting insights')
    parser.add_argument('file', nargs='?', help='Path to the log file')
    parser.add_argument('--examples', '-e', action='store_true', help='Show example entries for each pattern')
    parser.add_argument('--start-time', type=str, help='Start time in format "YYYY-MM-DD" or "YYYY-MM-DD HH:MM:SS"')
    parser.add_argument('--end-time', type=str, help='End time in format "YYYY-MM-DD HH:MM:SS"')
    parser.add_argument('--duration-minutes', type=int, help='Duration from start time in minutes (alternative to end time)')

    args = parser.parse_args()

    if not args.file:
        args.file = input("Please enter the path to the log file: ").strip()

    # Parse start time, allowing "YYYY-MM-DD" or "YYYY-MM-DD HH:MM:SS" formats
    if args.start_time:
        try:
            start_time = datetime.strptime(args.start_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            try:
                start_time = datetime.strptime(args.start_time, "%Y-%m-%d")
            except ValueError:
                print("Error: Start time must be in 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM:SS' format.")
                sys.exit(1)
    else:
        start_time = None

    # Calculate `end_time` from `duration_minutes` if provided, ensuring it's an alternative to `end_time`
    if args.duration_minutes is not None:
        if args.end_time:
            print("Error: Please provide either end time or duration in minutes, not both.")
            sys.exit(1)
        if not start_time:
            print("Error: Start time must be provided when using duration in minutes.")
            sys.exit(1)
        end_time = start_time + timedelta(minutes=args.duration_minutes)
    else:
        end_time = datetime.strptime(args.end_time, "%Y-%m-%d %H:%M:%S") if args.end_time else None

    analyzer = LogAnalyzer(show_examples=args.examples)
    analyzer.process_log_file(args.file, start_time=start_time, end_time=end_time)
    analyzer.generate_report()




if __name__ == "__main__":
    main()
