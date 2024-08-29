import json
from typing import Set, Dict, List
import re

def extract_log_ids(filename: str) -> Set[str]:
    log_ids = set()
    with open(filename, 'r') as file:
        for line in file:
            try:
                # Extract the JSON part from the log line
                json_match = re.search(r'\{.*\}', line)
                if json_match:
                    json_str = json_match.group(0)
                    data = json.loads(json_str)
                    if 'log_id' in data:
                        log_ids.add(data['log_id'])
            except json.JSONDecodeError:
                # Skip lines that are not valid JSON
                print(f"JSONDecodeError in line: {line}")
                continue
            except Exception as e:
                print(f"Error processing line: {line}")
                print(f"Error: {str(e)}")
    return log_ids

def compare_log_ids(file1: str, file2: str) -> Dict[str, List[str]]:
    ids1 = extract_log_ids(file1)
    ids2 = extract_log_ids(file2)

    only_in_file1 = list(ids1 - ids2)
    only_in_file2 = list(ids2 - ids1)

    return {
        'only_in_file1': only_in_file1,
        'only_in_file2': only_in_file2
    }

def main():
    file1 = 'threat_locust_json.log'
    file2 = 'detected_threats.log'

    result = compare_log_ids(file1, file2)

    f1Count = 0
    f2Count = 0

    print(f"Log IDs only in {file1}:")
    for log_id in result['only_in_file1']:
        print(log_id)
        f1Count += 1

    print(f1Count)

    print(f"\nLog IDs only in {file2}:")
    for log_id in result['only_in_file2']:
        print(log_id)
        f2Count += 1

    print(f2Count)

if __name__ == "__main__":
    main()
