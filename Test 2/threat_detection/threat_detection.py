import time
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

def check_for_threats():
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match_phrase": {"message": "Attack traffic"}},
                    {"range": {"@timestamp": {"gte": "now-1m"}}}
                ]
            }
        }
    }

    result = es.search(index="logs-*", body=query)

    if result['hits']['total']['value'] > 0:
        logger.warning(f"Detected {result['hits']['total']['value']} potential threats in the last minute!")
        for hit in result['hits']['hits']:
            logger.warning(f"Threat details: {hit['_source']['message']}")


if __name__ == "__main__":
    while True:
        check_for_threats()
        time.sleep(60)