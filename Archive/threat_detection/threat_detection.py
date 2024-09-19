import time
from datetime import datetime
from elasticsearch import Elasticsearch
import logging
from elasticsearch.exceptions import ConnectionError

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

def post_warning(message):
    doc = {
        '@timestamp': datetime.now().isoformat(),
        'message': message,
        'log_type': 'threat_detection_warning'
    }
    try:
        es.index(index=f"logs-{datetime.now():%Y.%m.%d}", body=doc)
        logger.info(f"Posted warning to Elasticsearch: {message}")
    except Exception as e:
        logger.error(f"Failed to post warning to Elasticsearch: {e}")


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

    try:
        result = es.search(index="logs-*", body=query)

        if result['hits']['total']['value'] > 0:
            warning_message = f"Detected {result['hits']['total']['value']} potential threats in the last minute!"
            logger.warning(warning_message)
            post_warning(warning_message)

            for hit in result['hits']['hits']:
                threat_detail = f"Threat details: {hit['_source']['message']}"
                logger.warning(threat_detail)
                post_warning(threat_detail)

    except Exception as e:
        logger.error(f"Error checking for threats: {e}")


if __name__ == "__main__":
    while True:
        check_for_threats()
        time.sleep(30)