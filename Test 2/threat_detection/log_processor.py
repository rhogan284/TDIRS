import time
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def connect_to_elasticsearch(max_retries=5, delay=10):
    for attempt in range(max_retries):
        try:
            es = Elasticsearch(["http://elasticsearch:9200"])
            es.info()
            logger.info("Successfully connected to Elasticsearch")
            return es
        except ConnectionError:
            logger.warning(f"Failed to connect to Elasticsearch. Attempt {attempt + 1} of {max_retries}")
            if attempt < max_retries - 1:
                time.sleep(delay)
    raise Exception("Failed to connect to Elasticsearch after multiple attempts")


es = connect_to_elasticsearch()


def fetch_logs(time_range_minutes=5):
    end_time = datetime.now()
    start_time = end_time - timedelta(minutes=time_range_minutes)

    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": start_time.isoformat(),
                    "lte": end_time.isoformat()
                }
            }
        },
        "sort": [
            {"@timestamp": "asc"}
        ]
    }

    try:
        result = es.search(index="logs-*", body=query)
        return result['hits']['hits']
    except Exception as e:
        logger.error(f"Error fetching logs: {e}")
        return []


def process_logs(logs):
    # TODO: Threat detection algorithm
    for log in logs:
        print(f"Log: {log['_source']}")

    # TODO: Implement threat detection logic here


def main():
    while True:
        logs = fetch_logs()
        process_logs(logs)
        time.sleep(30)


if __name__ == "__main__":
    main()