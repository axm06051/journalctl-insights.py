# journalctl-insights

a Python script designed to parse and analyze `JournalCtl` log files for recurring patterns, service status updates, error types, and log severity levels. This tool assists system administrators in troubleshooting and understanding system events, quickly identifying critical issues, and gaining insights from log data.

## Features

- **Pattern Identification**: Identifies and normalizes recurring log patterns for streamlined analysis.
- **Service Status Tracking**: Tracks service start, stop, and failure events.
- **Error Pattern Analysis**: Detects known error types (e.g., connection issues, permission errors).
- **Severity Scoring**: Rates log entries by severity for quick issue prioritization.
- **Customizable Date Range**: Analyzes specific timeframes using start/end time or duration in minutes.
- **Markdown Report Generation**: Outputs a markdown-styled report detailing log statistics and critical issues.
  
## Requirements

- Python 3.7 or higher

## Usage

### Basic Usage

```bash
python3 LogAnalyzer.py <log_file> [--options]
```

### Options

- `file`: **Required**. Path to the log file.
- `-e`, `--examples`: Show example entries for each detected pattern.
- `--start-time <date/time>`: Start time in `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS` format.
- `--end-time <date/time>`: End time in `YYYY-MM-DD HH:MM:SS` format.
- `--duration-minutes <minutes>`: Analysis duration in minutes (alternative to `end-time`, requires `start-time`).

**Note**: Either `end-time` or `duration-minutes` can be specified, but not both.

### Examples

1. **Basic Analysis**:

   ```bash
   python3 LogAnalyzer.py /path/to/logfile.log
   ```

2. **Analysis with Time Range**:

   ```bash
   python3 LogAnalyzer.py /path/to/logfile.log --start-time "2023-10-01" --end-time "2023-10-02 12:00:00"
   ```

3. **Analysis with Duration from Start Time**:

   ```bash
   python3 LogAnalyzer.py /path/to/logfile.log --start-time "2023-10-01 10:00:00" --duration-minutes 120
   ```

4. **Analysis with Examples**:

   ```bash
   python3 LogAnalyzer.py /path/to/logfile.log --examples
   ```

## Output

The script outputs a Markdown-style report detailing:

- **Critical Issues**: Highlights top critical log entries.
- **Service Status**: Shows service start/stop/failure counts.
- **Log Patterns**: Lists recurring patterns with example entries if `--examples` is enabled.
- **Log Level Distribution**: Summarizes log entries by severity level.
- **Error Type Analysis**: Categorizes and counts common error types.

## Error Handling

The script handles invalid timestamps, missing files, and unsupported date formats. Ensure the date format complies with `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`.
