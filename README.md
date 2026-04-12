# l2t-audit-extractor

**l2t-audit-extractor** is a lightweight Python utility designed to extract, filter, and summarize Windows Security Audit and TerminalServices (RDP) logs from **Plaso (log2timeline)** CSV exports. It is specifically optimized for rapid triage in Digital Forensics and Incident Response (DFIR) workflows.

## Key Features

* **Logon Statistics Generation**: Automatically aggregates logon/logoff events into a clean, human-readable summary.
* **RDP Session Tracking**: Specifically tracks Remote Desktop activity by correlating ActivityIDs from XML event data.
* **Artifact Extraction**: Filters specific Event IDs related to service creation, log clearing, and other notable activities.
* **Spreadsheet Friendly**: Outputs statistics in Tab-Separated Values (TSV) format for easy pasting into Excel or Google Sheets.

## Usage

```bash
python3 l2t_audit_extractor.py --target <target_directory> --start <YYYY-MM-DD> --end <YYYY-MM-DD> --output <output_dir>

## Development Status
This tool is a personal utility developed for rapid triage in DFIR engagements. It is provided "as-is" and is currently in maintenance mode. While it excels at common Plaso CSV patterns, it may not cover every edge case or localized Windows Event log variation.

## Future Direction
I am currently focusing my development efforts on a more robust, high-performance ecosystem:
* **podarge**: A lightweight Windows artifact collector written in Go.
* **ingestor**: A cloud-native forensics processing pipeline (currently transitioning from AWS to GCP).

This script remains public as a lightweight option for those utilizing traditional log2timeline workflows.
