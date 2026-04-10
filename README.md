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
