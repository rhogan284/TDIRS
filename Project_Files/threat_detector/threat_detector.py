import json
import re
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
import os
import logging
import yaml
import time
import uuid
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

log_dir = '/mnt/logs'
os.makedirs(log_dir, exist_ok=True)

threat_logger = logging.getLogger('threat_logger')
threat_logger.setLevel(logging.WARNING)
file_handler = logging.FileHandler(os.path.join(log_dir, 'detected_threats.log'))
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
threat_logger.addHandler(file_handler)

threat_logger.propagate = False

class ThreatDetector:
    def __init__(self, config_path='config.yaml'):
        self.config = self.load_config(config_path)
        self.es = self.connect_to_elasticsearch()
        self.compiled_rules = self.compile_rules()
        self.request_timestamps = defaultdict(lambda: deque(maxlen=self.config['ddos']['max_requests']))
        self.last_processed_timestamp = self.get_last_processed_timestamp()

    @staticmethod
    def load_config(config_path):
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)

    def connect_to_elasticsearch(self):
        es_host = os.environ.get('ELASTICSEARCH_HOST', 'elasticsearch')
        es_port = os.environ.get('ELASTICSEARCH_PORT', '9200')
        es = Elasticsearch([f"http://{es_host}:{es_port}"])
        es.info()
        logger.info("Successfully connected to Elasticsearch")
        return es

    def get_last_processed_timestamp(self):
        try:
            with open('/mnt/logs/last_processed_timestamp.txt', 'r') as f:
                return datetime.fromisoformat(f.read().strip())
        except FileNotFoundError:
            return datetime.now(timezone.utc) - timedelta(minutes=5)

    def save_last_processed_timestamp(self, timestamp):
        with open('/mnt/logs/last_processed_timestamp.txt', 'w') as f:
            f.write(timestamp.isoformat())

    def compile_rules(self):
        return {
            threat_type: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
            for threat_type, patterns in self.config['detection_rules'].items()
        }

    def detect_threats(self, log_entry):
        threats = set()
        url = log_entry.get('url', '')
        method = log_entry.get('method', '')
        request_body = json.dumps(log_entry.get('request_body', {}))
        headers = json.dumps(log_entry.get('request_headers', {}))
        client_ip = log_entry.get('client_ip', '')
        timestamp = datetime.now(timezone.utc)

        content_to_check = f"{url} {request_body} {headers}"

        for threat_type, patterns in self.compiled_rules.items():
            if threat_type != "ddos" and any(pattern.search(content_to_check) for pattern in patterns):
                threats.add(threat_type)

        if method == 'POST' and '/login' in url:
            threats.add('potential_brute_force')

        if '/exec' in url and 'cmd' in url:
            threats.add('command_injection')

        # DDoS detection
        self.request_timestamps[client_ip].append(timestamp)

        self.request_timestamps[client_ip] = deque(
            filter(lambda ts: timestamp - ts <= timedelta(seconds=self.config['ddos']['time_window']),
                   self.request_timestamps[client_ip]),
            maxlen=self.config['ddos']['max_requests']
        )

        if len(self.request_timestamps[client_ip]) > self.config['ddos']['threshold']:
            threats.add('ddos')
        elif len(self.request_timestamps[client_ip]) > 1:
            threats.add('potential_ddos')

        return list(threats)

    def reorder_log_fields(self, log_entry):
        ordered_log = {}
        for field in self.config['field_order']:
            if field in log_entry:
                ordered_log[field] = log_entry[field]
            elif field == "log_id":
                ordered_log[field] = str(uuid.uuid4())
            elif field == "threat_type":
                ordered_log[field] = log_entry.get("type", "unknown")

        for key, value in log_entry.items():
            if key not in ordered_log:
                ordered_log[key] = value

        return ordered_log

    def process_logs_batch(self, logs):
        actions = []
        for log in logs:
            threats = self.detect_threats(log['_source'])
            reordered_log = self.reorder_log_fields(log['_source'])
            if threats:
                reordered_log['detected_threats'] = threats
                actions.append({
                    "_index": self.config['indices']['threat'],
                    "_source": reordered_log
                })
                threat_message = f"Threat detected: {threats} in log: {reordered_log.get('url', 'N/A')} from IP: {reordered_log.get('client_ip', 'N/A')}"
                logging.warning(threat_message)
                threat_logger.warning(json.dumps(reordered_log))
            else:
                actions.append({
                    "_index": self.config['indices']['normal'],
                    "_source": reordered_log
                })
                logging.info(
                    f"Normal log processed: {reordered_log.get('url', 'N/A')} from IP: {reordered_log.get('client_ip', 'N/A')}")

        if actions:
            try:
                success, failed = bulk(self.es, actions)
                logger.info(f"Indexed {success} logs. Failed: {len(failed)}")
            except Exception as e:
                logger.error(f"Error during bulk indexing: {str(e)}")

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

        result = self.es.search(index=self.config['indices']['source'], query=query, sort=[{"@timestamp": "asc"}],
                                size=self.config['processing']['batch_size'])
        logging.info(f"Retrieved {len(result['hits']['hits'])} new logs from Elasticsearch")
        return result['hits']['hits']

    def run(self):
        while True:
            try:
                logs = self.get_new_logs()
                if logs:
                    self.process_logs_batch(logs)
                    last_log = logs[-1]['_source']
                    self.last_processed_timestamp = datetime.fromisoformat(last_log['@timestamp'].replace('Z', '+00:00'))
                    self.save_last_processed_timestamp(self.last_processed_timestamp)
                    logger.info(f"Processed {len(logs)} logs. Last processed timestamp: {self.last_processed_timestamp.isoformat()}")
                else:
                    logger.info("No new logs to process.")
                time.sleep(self.config['processing']['poll_interval'])
            except Exception as e:
                logger.error(f"An error occurred: {str(e)}")
                logger.info("Attempting to reconnect to Elasticsearch...")
                self.es = self.connect_to_elasticsearch()
                time.sleep(self.config['processing']['error_retry_interval'])


if __name__ == "__main__":
    detector = ThreatDetector()
    detector.run()
