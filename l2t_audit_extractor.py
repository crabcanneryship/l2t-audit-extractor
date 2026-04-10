"""
l2t_audit_extractor.py: Generate logon statistics and collect audit related records
    from log2timeline/plaso CSV, focusing on Security Audit & TerminalServices logs.

Usage:
    python3 l2t_audit_extractor.py --target <target directory> --start <date_range_start>
    --end <date_range_end> --output <output_dir>

Results:
    - stats.txt     : Comprehensive statistics of logon/logoff events.
    - audits.csv    : Filtered subset of audit-related raw records.
    - rdp_stats.txt : Logon/logoff statistics specifically for Remote Desktop sessions.
    - rdp_audits.csv: Raw audit records filtered for Remote Desktop activity.
    - services.csv  : Extracted service-related event records (e.g., Service installation).
    Note: Stats files are in tab separated values format to be easily pasted to a Spreadsheet.

Notes:
    - Environment Specifics: CSV column indices are optimized for the default log2timeline
      output schema. Adjustments may be required if dynamic headers customizations applied.
    - DateTime Filtering: --start and --end parameters expect ISO 8601, 'YYYY-MM-DD' or
      'YYYY-MM-DDThh:mm:ss'.
    - XML Parsing: Based on modern Windows XML structures. Old versions (pre-Win10) 
      may require manual tuning of tab characters (\t) or tag paths.
    - Performance: Designed for rapid triage; may need optimization for multi-GB logs.
"""
import datetime
import os
import re
import sys
import argparse
import logging

# --- Configuration Defaults (Hard-coded for environmental persistence) ---
DEF_TGT = '/home/timelines/' # Default directory to collect
DEF_START = '2020-01-01T00:00:00' # Default date range: start
DEF_END = '2026-12-31T23:59:59' # Default date range: end
DEF_OUT = './output' # Default output base directory
FILE_PTN = r'l2t_(.+)_psorted\.csv' # CSV filename convention 
NEW_PTN = r'New Logon:\\n\\t?(.+)\\n\\nProcess Information:\\n'
ID_PTN = r'\\tLogon ID:\\t\\t?(0x[0-9a-f]{16})\\n'
ACT_PTN = r'\\tAccount Name:\\t\\t?([a-zA-Z0-9\-_\. ]{1,20}\$*)\\n'
WS_PTN = r'\\tWorkstation Name:\\t?([a-zA-Z0-9\-_\.]{1,20})\\n'
SRC_PTN = r'\\tSource Network Address:\\t' \
          r'?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|\-|[:0-9a-z]{2,40})\\n'
TYPE_PTN = r'\\tLogon Type:\\t\\t?([0-9]{1,2})\\n'

# --- Logon types to record in stats (Interactive, Network, Unlock, and Remote) ---
LOGON_TYPES_FOR_STATS = {'2', '3', '7', '10'}

# --- Event IDs for Security Auditing ---
AUDIT_EVENT_IDS = {
    '[4624 /', '[4625 /', '[4634 /', '[4647 /', '[4648 /',
    '[4672 /', '[4768 /', '[4769 /', '[4771 /', '[4776 /',
}
# --- Event IDs for Service related events (Currently creation only) ---
SERVICE_EVENT_IDS = {'[4697 /'}
# --- Event IDs for other notable events such as process, task and log clear ---
OTHER_EVENT_IDS = {
    '[4688 /', '[4698 /', '[4702 /', '[4720 /', '[4722 /',
    '[4728 /', '[1102 /', '[4719 /',
}
# --- Combined Event IDs ---
ALL_AUDIT_IDS = AUDIT_EVENT_IDS | SERVICE_EVENT_IDS | OTHER_EVENT_IDS

# --- Regex Patterns: Specifically for RDP Session Tracking (TerminalServices) ---
RDP_ID_PTN = r'Correlation ActivityID=\"\{?([0-9A-Z]{8}\-[0-9A-Z]{4}\-[0-9A-Z]{4}\-[0-9A-Z]{4}\-[0-9A-Z]{12})\}\"'
RDP_ACT_PTN = r'<User>?([a-zA-Z0-9\-_\.\\]{1,50})</User>'
RDP_SRC_PTN = r'<Address>?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})</Address>'
RDP_AUDIT_IDS = {'[21 /', '[23 /', '[24 /', '[25 /', '[39 /', '[40 /'}

def setup_logger():
    """Initializes the logger for both console and file output.

    Returns:
        logging.Logger: Configured logger instance with a standard format.
    """
    logger = logging.getLogger('AuditExtractor')
    logger.setLevel(logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    
    # Console Handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    
    return logger

def create_message(ln):
    """Creates a standard CSV formatted record for audit events.

    Args:
        ln (list): A list representing a single row from a log2timeline CSV.

    Returns:
        str: A re-constructed comma-separated string of key forensic fields:
             (datetime, timezone, MACB, category, timestamp_desc, hostname, message)
    """
    # Note: Column 5 and 7 are 'source' and 'hostname' in standard l2tcsv
    return f'{ln[0]},{ln[1]},{ln[2]},{ln[3]},{ln[5]},{ln[7]},{ln[9]}'

def create_message_rdp(ln):
    """Creates a record specifically for RDP events, including XML data.

    Args:
        ln (list): A list representing a single row from a log2timeline CSV.

    Returns:
        str: A re-constructed comma-separated string of key forensic fields:
             (datetime, timezone, MACB, category, timestamp_desc, hostname, message, XML)
    """
    return f'{ln[0]},{ln[1]},{ln[2]},{ln[3]},{ln[5]},{ln[7]},{ln[9]},{ln[15]}'

def get_item(pattern, message):
    """Extracts a specific value from a string using a regex pattern.

    Args:
        pattern (str): The compiled regex pattern or raw string pattern.
        message (str): The target string to search within.

    Returns:
        str: The first captured group if a match is found; otherwise, an empty string.
    """
    value = ''
    result = re.search(pattern, message)
    if result:
        value = result.group(1)
    return value

def ensure_dir(path):
    """Checks if a directory exists and creates it if necessary.

    Args:
        path (str): The directory path to verify or create.
    """
    if not os.path.exists(path):
        os.makedirs(path)

def main():
    # Argument definitions
    parser = argparse.ArgumentParser(description='Extract Windows Audit events from Plaso CSV timelines.')
    parser.add_argument('--target', default=DEF_TGT, help='Directory containing timeline CSVs')
    parser.add_argument('--start', default=DEF_START, help='Start time (ISO format)')
    parser.add_argument('--end', default=DEF_END, help='End time (ISO format)')
    parser.add_argument('--output', default=DEF_OUT, help='Base directory for output')
    args = parser.parse_args()

    # Prepare logger
    logger = setup_logger()

    # Validation check for the target directory
    if not os.path.exists(args.target) or not os.path.isdir(args.target):
        logger.error(f'Target directory "{args.target}" not found.')
        return

    # Get date range to search
    try:
        starting_time = datetime.datetime.strptime(args.start, '%Y-%m-%dT%H:%M:%S')
        ending_time = datetime.datetime.strptime(args.end, '%Y-%m-%dT%H:%M:%S')
    except ValueError as e:
        logger.error(f'Invalid date format: {e}')
        return

    # Iterate through the target directory to identify relevant Plaso CSV files
    for filename in os.listdir(args.target):
        stats, rdp_stats = {}, {}
        audits, rdp_audits, services = [], [], []

        # Identify server name from CSV filename convention.
        result = re.match(FILE_PTN, filename)
        if not result:
            continue

        server = result.group(1)
        logger.info(f'Processing: {filename} (Server: {server})')

        # Read and process each log file
        # Note: Parsing logic relies on default Plaso l2tcsv columns (Index 9: Message, 15: XML)
        input_path = os.path.join(args.target, filename)
        with open(input_path, 'r', encoding='utf-8-sig') as f:
            started = False
            for line_content in f:
                line = line_content.rstrip('\n').split(',')
                if len(line) < 10: continue

                try:
                    logtime = datetime.datetime.strptime(line[0], '%Y-%m-%dT%H:%M:%S')
                except ValueError: continue

                if not started:
                    if logtime >= starting_time: started = True
                    else: continue
                
                if logtime > ending_time: break

                message = line[9]
                xml = line[15] if len(line) > 15 else ''

                # Parse Windows Security Auditing events (specifically ID 4624/4634/4647).
                if 'Microsoft-Windows-Security-Auditing' in message:
                    matched_id = next((eid for eid in ALL_AUDIT_IDS if message.startswith(eid)), None)
                    if matched_id:
                        if message.startswith('[4624 /'):
                            new_res = re.search(NEW_PTN, message)
                            if new_res:
                                new_logon = new_res.group(1)
                                log_id = get_item(ID_PTN, new_logon)
                                if log_id:
                                    logon_type = get_item(TYPE_PTN, message)
                                    if logon_type in LOGON_TYPES_FOR_STATS and log_id not in stats:
                                        stats[log_id] = {
                                            'logon': line[0], 'logoff': '',
                                            'logon_type': logon_type, 'account_name': get_item(ACT_PTN, new_logon),
                                            'workstation': get_item(WS_PTN, message), 'source_address': get_item(SRC_PTN, message)
                                        }
                            audits.append(create_message(line))
                        elif message.startswith('[4634 /') or message.startswith('[4647 /'):
                            log_id = get_item(ID_PTN, message)
                            if log_id in stats and not stats[log_id]['logoff']:
                                stats[log_id]['logoff'] = line[0]
                            audits.append(create_message(line))
                        elif message.startswith('[4697 /'):
                            services.append(create_message(line))
                        else:
                            audits.append(create_message(line))

                # Process Remote Desktop records
                elif 'Microsoft-Windows-TerminalServices-LocalSessionManager' in message:
                    if any(message.startswith(eid) for eid in RDP_AUDIT_IDS):
                        if message.startswith('[21 /'):
                            log_id = get_item(RDP_ID_PTN, xml)
                            if log_id and log_id not in rdp_stats:
                                rdp_stats[log_id] = {
                                    'logon': line[0], 'logoff': '',
                                    'user': get_item(RDP_ACT_PTN, xml), 'address': get_item(RDP_SRC_PTN, xml)
                                }
                        elif message.startswith('[23 /') or message.startswith('[24 /'):
                            log_id = get_item(RDP_ID_PTN, xml)
                            if log_id in rdp_stats and not rdp_stats[log_id]['logoff']:
                                rdp_stats[log_id]['logoff'] = line[0]
                        
                        audits.append(create_message(line))
                        rdp_audits.append(create_message_rdp(line))

        # Write results to files, firstly prepare output directory
        out_dir = os.path.join(args.output, server)
        if audits or services or rdp_audits or stats or rdp_stats:
            ensure_dir(out_dir)

        # Export raw audit records to CSV.
        if audits:
            with open(os.path.join(out_dir, 'audits.csv'), 'w', encoding='utf-8') as f:
                f.write('datetime,timezone,MACB,category,timestamp_desc,hostname,message\n')
                for item in audits:
                    f.write(item + '\n')

        # Export raw service records to CSV.
        if services:
            with open(os.path.join(out_dir, 'services.csv'), 'w', encoding='utf-8') as f:
                f.write('datetime,timezone,MACB,category,timestamp_desc,hostname,message\n')
                for item in services:
                    f.write(item + '\n')

        # Export raw RDP records to CSV.
        if rdp_audits:
            with open(os.path.join(out_dir, 'rdp_audits.csv'), 'w', encoding='utf-8') as f:
                f.write('datetime,timezone,MACB,category,timestamp_desc,hostname,message,XML\n')
                for item in rdp_audits:
                    f.write(item + '\n')

        # Export audit stats to TSV.
        if stats:
            stats_array = []
            for k, v in stats.items():
                stats_array.append(
                    f'{v["logon"]}\t{v["logoff"]}\t'
                    f'{v["logon_type"]}\t{v["account_name"]}\t'
                    f'{v["workstation"]}\t{v["source_address"]}\t{k}'
                )
            stats_array.sort()
            with open(os.path.join(out_dir, 'stats.txt'), 'w', encoding='utf-8') as f:
                f.write('Logon Time\tLogoff Time\tLogon Type\tAccount Name\t'
                        'Workstation Name\tSource Network Address\tLogon ID\n')
                for item in stats_array:
                    f.write(item + '\n')
        
        # Export RDP stats to TSV.
        if rdp_stats:
            rdp_stats_array = []
            for k, v in rdp_stats.items():
                rdp_stats_array.append(
                    f'{v["logon"]}\t{v["logoff"]}\t'
                    f'{v["user"]}\t{v["address"]}\t{k}'
                )
            rdp_stats_array.sort()
            with open(os.path.join(out_dir, 'rdp_stats.txt'), 'w', encoding='utf-8') as f:
                f.write('Logon Time\tLogoff Time\tUser\tAddress\tCorrelation ID\n')
                for item in rdp_stats_array:
                    f.write(item + '\n')

        logger.info(f'Completed {server}: Stats={len(stats)}, RDP={len(rdp_stats)}')

if __name__ == '__main__':
    main()