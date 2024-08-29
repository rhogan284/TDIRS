import json
from typing import Dict, List, Tuple


def extract_log_info(filename: str) -> Dict[str, str]:
    log_info = {}
    with open(filename, 'r') as file:
        for line in file:
            try:
                # Try to parse the entire line as JSON first
                data = json.loads(line)
                log_id = data.get('log_id')
                threat_type = data.get('threat_type', 'Unknown')

                # If log_id is not present, it might be in a nested structure
                if not log_id and 'log' in data:
                    log_data = json.loads(data['log'])
                    log_id = log_data.get('log_id')
                    threat_type = log_data.get('threat_type', threat_type)

                if log_id:
                    log_info[log_id] = threat_type
            except json.JSONDecodeError:
                # If the entire line is not JSON, try splitting by ' - ' and parse the second part
                try:
                    _, json_part = line.split(' - ', 1)
                    data = json.loads(json_part)
                    log_id = data.get('log_id')
                    threat_type = data.get('threat_type', 'Unknown')
                    if log_id:
                        log_info[log_id] = threat_type
                except (json.JSONDecodeError, ValueError, IndexError):
                    print(f"Error processing line: {line.strip()}")
    return log_info


def compare_log_info(file1: str, file2: str) -> Dict[str, List[Tuple[str, str]]]:
    info1 = extract_log_info(file1)
    info2 = extract_log_info(file2)

    only_in_file1 = [(log_id, threat_type) for log_id, threat_type in info1.items() if log_id not in info2]
    only_in_file2 = [(log_id, threat_type) for log_id, threat_type in info2.items() if log_id not in info1]

    return {
        'only_in_file1': only_in_file1,
        'only_in_file2': only_in_file2
    }


def main():
    file1 = 'threat_locust_json.log'
    file2 = 'detected_threats.log'

    result = compare_log_info(file1, file2)

    f1Count = 0
    f2Count = 0

    print(f"Log IDs and threat types only in {file1}:")
    for log_id, threat_type in result['only_in_file1']:
        print(f"Log ID: {log_id}, Threat Type: {threat_type}")
        f1Count += 1

    print(f"Total count in {file1}: {f1Count}")

    print(f"\nLog IDs and threat types only in {file2}:")
    for log_id, threat_type in result['only_in_file2']:
        print(f"Log ID: {log_id}, Threat Type: {threat_type}")
        f2Count += 1

    print(f"Total count in {file2}: {f2Count}")


if __name__ == "__main__":
    main()