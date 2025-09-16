# Log Analysis Automation (Python)

## Overview
This project automates scanning security logs for **known malicious IP addresses**.  
Instead of manually reviewing logs, the script flags suspicious entries and writes a report—saving time for SOC analysts and reducing alert fatigue.

## Tools & Technologies
- Python 3
- Files: `bad_ips.txt`, `logs/sample_logs.txt`
- Output: `output/flagged_entries.txt`

## How It Works
1. Load a list of bad IPs from `bad_ips.txt`.
2. Parse each line of `logs/sample_logs.txt`.
3. Flag log entries that contain a bad IP.
4. Print alerts to console and write a timestamped report to `output/flagged_entries.txt`.

## Running the Script
```bash
python3 log_parser.py
