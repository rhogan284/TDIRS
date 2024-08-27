import json
import re
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch
import time
import os
import logging
from urllib3.exceptions import NewConnectionError
from elasticsearch.exceptions import ConnectionError as ElasticsearchConnectionError

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

log_dir = '/mnt/logs'
os.makedirs(log_dir, exist_ok=True)

threat_logger = logging.getLogger('threat_logger')
threat_logger.setLevel(logging.WARNING)
file_handler = logging.FileHandler(os.path.join(log_dir, 'detected_threats.log'))
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
threat_logger.addHandler(file_handler)


class ThreatDetector:
    def __init__(self):
        self.es = None
        self.connect_to_elasticsearch()
        self.detection_rules = {
            "sql_injection": [
                r"(?i)id=\s*['\"].*?(?:--|\%27|')",  # Basic SQL injection
                r"(?i)UNION\s+SELECT",  # UNION-based SQL injection
                r"(?i)EXEC\s*\(",  # Execution of stored procedures
                r"(?i)WAITFOR\s+DELAY",  # Time-based SQL injection
                r"(?i)SELECT\s+.*?FROM",  # SELECT statements
                r"(?i)1\s*=\s*1",  # Tautologies
                r"(?i)DROP\s+TABLE",  # Table dropping attempts
                r"(?i);.*?(?:SELECT|INSERT|UPDATE|DELETE|DROP)"  # Piggybacked queries
            ],
            "xss": [
                r"(?i)<script>",  # Basic XSS
                r"(?i)javascript:",  # JavaScript protocol
                r"(?i)alert\s*\(",  # Alert functions
                r"(?i)on\w+\s*=",  # Event handlers
                r"(?i)<svg.*?on\w+\s*=",  # SVG-based XSS
                r"(?i)<img.*?on\w+\s*=",  # Image-based XSS
                r"(?i)\"\s*><script>",  # Quote breaking XSS
                r"(?i)'\s*><script>"  # Single quote breaking XSS
            ],
            "path_traversal": [
                r"(?i)\.\.\/",  # Unix-style path traversal
                r"(?i)\.\.\\",  # Windows-style path traversal
                r"(?i)\.\.%2f",  # URL encoded ../
                r"(?i)\.\.%5c",  # URL encoded ..\
                r"(?i)%2e%2e%2f",  # Double URL encoded ../
                r"(?i)%252e%252e%252f"  # Triple URL encoded ../
                r"(?i)\.\.(?:%2f|%5c|/|\\)",  # Mixed encoding: '..' followed by encoded or raw slash
                r"(?i)(?:%2e|%252e){2,}(?:%2f|%5c|/|\\)"  # Multiple encoded dots followed by encoded or raw slash
            ],
            "command_injection": [
                r"(?i);\s*\w+",  # Command chaining with semicolon
                r"(?i)`.*?`",  # Backtick execution
                r"(?i)\|\s*\w+",  # Pipe to command
                r"(?i)\$\(.*?\)",  # Command substitution
                r"(?i)&&\s*\w+",  # Command chaining with &&
                r"(?i)\|\|\s*\w+"  # Command chaining with ||
            ],
            "potential_brute_force": [
                r"/login"  # Login attempts
            ],
            "ddos": [
                r"/"  # Homepage
                r"/login",  # Login page
                r"/search",  # Search functionality
                r"/products",  # Product listing
                r"/cart",  # Shopping cart
                r"/checkout"  # Checkout process
            ]
        }
        self.source_index = "locust-logs-*"
        self.threat_index = "threat-logs"
        self.normal_index = "normal-logs"
        self.last_processed_timestamp = self.get_last_processed_timestamp()
        self.request_timestamps = defaultdict(list)
        self.ddos_threshold = 5
        self.ddos_time_window = 2

    def get_last_processed_timestamp(self):
        # Try to read the last processed timestamp from a file
        try:
            with open('/mnt/logs/last_processed_timestamp.txt', 'r') as f:
                return datetime.fromisoformat(f.read().strip())
        except FileNotFoundError:
            # If the file doesn't exist, return a timestamp from 5 minutes ago
            return datetime.now(timezone.utc) - timedelta(minutes=5)

    def save_last_processed_timestamp(self, timestamp):
        with open('/mnt/logs/last_processed_timestamp.txt', 'w') as f:
            f.write(timestamp.isoformat())

    def connect_to_elasticsearch(self):
        max_retries = 5
        retry_delay = 10  # seconds

        for attempt in range(max_retries):
            try:
                self.es = Elasticsearch([
                    f"http://{os.environ.get('ELASTICSEARCH_HOST', 'elasticsearch')}:{os.environ.get('ELASTICSEARCH_PORT', '9200')}"])
                self.es.info()  # This will raise an exception if the connection fails
                print("Successfully connected to Elasticsearch")
                return
            except (NewConnectionError, ElasticsearchConnectionError) as e:
                print(f"Connection attempt {attempt + 1} failed: {str(e)}")
                if attempt < max_retries - 1:
                    print(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    print("Max retries reached. Unable to connect to Elasticsearch.")
                    raise

    def detect_threats(self, log_entry):
        threats = set()
        url = log_entry.get('url', '')
        method = log_entry.get('method', '')
        request_body = json.dumps(log_entry.get('request_body', {}))
        headers = json.dumps(log_entry.get('request_headers', {}))
        client_ip = log_entry.get('client_ip', '')
        timestamp = datetime.fromisoformat(log_entry.get('@timestamp').replace('Z', '+00:00'))

        content_to_check = f"{url} {request_body} {headers}"

        for threat_type, patterns in self.detection_rules.items():
            if threat_type != "ddos":
                for pattern in patterns:
                    if re.search(pattern, content_to_check, re.IGNORECASE):
                        threats.add(threat_type)
                        break

        if method == 'POST' and '/login' in url:
            threats.add('potential_brute_force')

        if '/exec' in url and 'cmd' in url:
            threats.add('command_injection')

        self.request_timestamps[client_ip].append(timestamp)

        self.request_timestamps[client_ip] = [
            ts for ts in self.request_timestamps[client_ip]
            if timestamp - ts <= timedelta(seconds=self.ddos_time_window)
        ]

        if len(self.request_timestamps[client_ip]) > 1:
            if len(self.request_timestamps[client_ip]) > self.ddos_threshold:
                threats.add('ddos')
            else:
                threats.add('potential_ddos')

        return list(threats)

    def process_log(self, log_entry):
        threats = self.detect_threats(log_entry)
        if threats:
            log_entry['detected_threats'] = threats
            self.es.index(index=self.threat_index, document=log_entry)
            threat_message = f"Threat detected: {threats} in log: {log_entry.get('url', 'N/A')} from IP: {log_entry.get('client_ip', 'N/A')}"
            logger.warning(threat_message)
            threat_logger.warning(json.dumps(log_entry))
        else:
            self.es.index(index=self.normal_index, document=log_entry)
            logger.info(
                f"Normal log processed: {log_entry.get('url', 'N/A')} from IP: {log_entry.get('client_ip', 'N/A')}")

    def get_new_logs(self):
        query = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gt": self.last_processed_timestamp.isoformat()
                            }
                        }
                    }
                ]
            }
        }

        result = self.es.search(index=self.source_index, query=query, sort=[{"@timestamp": "asc"}], size=10000)
        logger.info(f"Retrieved {len(result['hits']['hits'])} new logs from Elasticsearch")
        return result['hits']['hits']

    def run(self):
        while True:
            try:
                logs = self.get_new_logs()
                for log in logs:
                    self.process_log(log['_source'])
                    log_timestamp = datetime.fromisoformat(log['_source']['@timestamp'].replace('Z', '+00:00'))
                    self.last_processed_timestamp = max(self.last_processed_timestamp, log_timestamp)

                if logs:
                    self.save_last_processed_timestamp(self.last_processed_timestamp)
                    logger.info(
                        f"Processed {len(logs)} logs. Last processed timestamp: {self.last_processed_timestamp.isoformat()}")
                else:
                    logger.info("No new logs to process.")

                time.sleep(30)
            except Exception as e:
                logger.error(f"An error occurred: {str(e)}")
                logger.info("Attempting to reconnect to Elasticsearch...")
                self.connect_to_elasticsearch()


if __name__ == "__main__":
    detector = ThreatDetector()
    detector.run()
