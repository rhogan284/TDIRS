import json
import logging
import yaml
import time
import redis
import os
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
import sys

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.StreamHandler(sys.stderr),
                        logging.FileHandler("/mnt/logs/threat_responder.log")
                    ])
logger = logging.getLogger(__name__)

class ThreatResponder:
    def __init__(self, config_path='responder_config.yaml'):
        logger.info("Initializing ThreatResponder")
        self.config = self.load_config(config_path)
        self.es = self.connect_to_elasticsearch()
        self.redis = self.connect_to_redis()
        self.last_processed_timestamp = self.get_last_processed_timestamp()
        self.BLOCKED_IPS_KEY = f"{self.config['redis']['key_prefix']}blocked_ips"

    @staticmethod
    def load_config(config_path):
        logger.info(f"Loading config from {config_path}")
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        logger.info("Config loaded successfully")
        return config

    def connect_to_elasticsearch(self):
        es_host = os.environ.get('ELASTICSEARCH_HOST', 'elasticsearch')
        es_port = os.environ.get('ELASTICSEARCH_PORT', '9200')
        es = Elasticsearch([f"http://{es_host}:{es_port}"])
        es.info()
        logger.info("Successfully connected to Elasticsearch")
        return es

    def connect_to_redis(self):
        redis_url = os.environ.get('REDIS_URL', 'redis://redis:6379/0')
        logger.info(f"Connecting to Redis at {redis_url}")
        return redis.Redis.from_url(redis_url, decode_responses=True)

    def get_last_processed_timestamp(self):
        try:
            timestamp = self.redis.get('last_processed_timestamp')
            if timestamp:
                return datetime.fromisoformat(timestamp)
        except Exception as e:
            logger.error(f"Error getting last processed timestamp: {str(e)}")

        return datetime.utcnow() - timedelta(minutes=5)

    def save_last_processed_timestamp(self, timestamp):
        try:
            self.redis.set('last_processed_timestamp', timestamp.isoformat())
        except Exception as e:
            logger.error(f"Error saving last processed timestamp: {str(e)}")

    def get_new_threats(self):
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

        logger.info(f"Querying Elasticsearch for threats after {self.last_processed_timestamp.isoformat()}")
        logger.debug(f"Query: {json.dumps(query)}")

        result = self.es.search(
            index=self.config['indices']['threat'],
            query=query,
            sort=[{"@timestamp": "asc"}],
            size=self.config['processing']['batch_size']
        )

        threats = result['hits']['hits']
        logger.info(f"Retrieved {len(threats)} threats from Elasticsearch")

        if threats:
            logger.info(f"First threat timestamp: {threats[0]['_source']['@timestamp']}")
            logger.info(f"Last threat timestamp: {threats[-1]['_source']['@timestamp']}")

        return threats

    def execute_response(self, threat_type, log_entry):
        logger.info(f"Executing response for threat type: {threat_type}")
        if threat_type in self.config['response_actions']:
            action = self.config['response_actions'][threat_type]
            logger.info(f"Action for {threat_type}: {action}")

            client_ip = log_entry.get('client_ip', 'unknown')

            if action == "block_ip":
                self.block_ip(client_ip)
            elif action == "rate_limit":
                self.rate_limit_ip(client_ip)
            elif action == "log":
                self.log_threat(threat_type, client_ip)
            else:
                logger.warning(f"Unknown action type for threat: {threat_type}")
        else:
            logger.warning(f"No response action defined for threat type: {threat_type}")

    def block_ip(self, ip):
        logger.info(f"Blocking IP: {ip}")
        self.redis.sadd(self.BLOCKED_IPS_KEY, ip)
        self.redis.expire(self.BLOCKED_IPS_KEY, self.config['redis']['expiration_time'])
        logger.info(f"Blocked IP: {ip} for {self.config['redis']['expiration_time']} seconds")

    def rate_limit_ip(self, ip):
        logger.info(f"Rate limiting IP: {ip}")
        key = f"{self.config['redis']['key_prefix']}rate:{ip}"
        current = self.redis.get(key)
        if current is None:
            self.redis.set(key, 1, ex=self.config['rate_limit']['window_size'])
        elif int(current) < self.config['rate_limit']['max_requests']:
            self.redis.incr(key)
        else:
            self.block_ip(ip)
            logger.info(f"Rate limit exceeded for IP: {ip}. Blocking.")

    def log_threat(self, threat_type, ip):
        logger.info(f"Logging threat: {threat_type} from IP: {ip}")
        with open(self.config['logging']['file'], "a") as f:
            f.write(f"{datetime.now().isoformat()},{threat_type},{ip}\n")
        logger.info(f"Logged {threat_type} threat from IP: {ip}")

    def process_threats(self, threats):
        for threat in threats:
            log_entry = threat['_source']
            detected_threats = log_entry.get('detected_threats', [])
            client_ip = log_entry.get('client_ip')
            if client_ip and detected_threats:
                self.block_ip(client_ip)
                logger.info(f"Blocked IP {client_ip} due to threats: {', '.join(detected_threats)}")

        if threats:
            last_threat = threats[-1]['_source']
            self.last_processed_timestamp = datetime.fromisoformat(last_threat['@timestamp'].replace('Z', '+00:00'))
            self.save_last_processed_timestamp(self.last_processed_timestamp)

    def run(self):
        sync_interval = self.config.get('sync_interval', 300)  # Default to 5 minutes
        last_sync_time = time.time()

        while True:
            try:
                current_time = time.time()
                if current_time - last_sync_time > sync_interval:
                    self.sync_last_processed_timestamp()
                    last_sync_time = current_time

                threats = self.get_new_threats()
                if threats:
                    self.process_threats(threats)
                    logger.info(
                        f"Processed {len(threats)} threats. Last processed timestamp: {self.last_processed_timestamp.isoformat()}")
                else:
                    logger.info("No new threats to process.")
                time.sleep(self.config['processing']['poll_interval'])
            except Exception as e:
                logger.error(f"An error occurred: {str(e)}")
                logger.info("Attempting to reconnect to Elasticsearch...")
                self.es = self.connect_to_elasticsearch()
                time.sleep(self.config['processing']['error_retry_interval'])

    def sync_last_processed_timestamp(self):
        query = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "lte": datetime.utcnow().isoformat()
                            }
                        }
                    }
                ]
            }
        }

        result = self.es.search(
            index=self.config['indices']['threat'],
            query=query,
            sort=[{"@timestamp": "desc"}],
            size=1
        )

        if result['hits']['hits']:
            latest_timestamp = datetime.fromisoformat(
                result['hits']['hits'][0]['_source']['@timestamp'].replace('Z', '+00:00'))
            self.last_processed_timestamp = latest_timestamp
            self.save_last_processed_timestamp(latest_timestamp)
            logger.info(f"Synced last processed timestamp to {latest_timestamp.isoformat()}")
        else:
            logger.warning("No threats found in Elasticsearch during sync")


if __name__ == "__main__":
    responder = ThreatResponder()
    responder.run()