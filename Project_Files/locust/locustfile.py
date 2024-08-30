import random
import json
import logging
import time
import uuid
from locust import HttpUser, task, between
from locust.contrib.fasthttp import FastHttpUser
from datetime import datetime

json_logger = logging.getLogger('json_logger')
json_logger.setLevel(logging.INFO)
json_handler = logging.FileHandler('/mnt/logs/locust_json.log')
json_handler.setFormatter(logging.Formatter('%(message)s'))
json_logger.addHandler(json_handler)

class WebsiteUser(FastHttpUser):
    wait_time = between(1, 5)

    def on_start(self):
        self.user_id = str(uuid.uuid4())
        self.session_id = str(uuid.uuid4())
        self.client_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        self.user_agent = random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36'
        ])
        self.geolocation = random.choice([
            {"country": "United States", "city": "New York", "timezone": "America/New_York"},
            {"country": "United Kingdom", "city": "London", "timezone": "Europe/London"},
            {"country": "Japan", "city": "Tokyo", "timezone": "Asia/Tokyo"},
            {"country": "Australia", "city": "Sydney", "timezone": "Australia/Sydney"},
            {"country": "Germany", "city": "Berlin", "timezone": "Europe/Berlin"}
        ])

    @task(10)
    def index_page(self):
        self._log_request("GET", "/", None)

    @task(5)
    def view_product(self):
        product_id = random.randint(1, 10)
        self._log_request("GET", f"/products/{product_id}", None)

    @task(2)
    def add_to_cart(self):
        product_id = random.randint(1, 10)
        self._log_request("POST", "/cart", {"product_id": product_id, "quantity": 1})

    @task(2)
    def view_cart(self):
        self._log_request("GET", "/cart", None)

    @task(1)
    def checkout(self):
        self._log_request("POST", "/checkout", {"payment_method": "credit_card"})

    def _log_request(self, method, path, data):
        log_id = str(uuid.uuid4())
        start_time = time.time()
        try:
            if method == "GET":
                response = self.client.get(path)
            elif method == "POST":
                response = self.client.post(path, json=data)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            self._log_response(log_id, method, path, response, start_time, data)
        except Exception as e:
            self._log_exception(log_id, method, path, e, start_time, data)

    def _log_response(self, log_id, method, path, response, start_time, data):
        log_entry = {
            "log_id": log_id,
            "@timestamp": datetime.utcnow().isoformat(),
            "client_ip": self.client_ip,
            "method": method,
            "url": f"{self.host}{path}",
            "status_code": response.status_code,
            "response_time_ms": int((time.time() - start_time) * 1000),
            "bytes_sent": len(response.request.body) if response.request.body else 0,
            "bytes_received": len(response.content),
            "user_agent": self.user_agent,
            "referer": random.choice([None, "https://www.google.com", "https://www.bing.com"]),
            "request_headers": dict(response.request.headers),
            "response_headers": dict(response.headers),
            "geo": self.geolocation,
            "request_body": data if data else None
        }
        json_logger.info(json.dumps(log_entry))

    def _log_exception(self, log_id, method, path, exception, start_time, data):
        log_entry = {
            "log_id": log_id,
            "@timestamp": datetime.utcnow().isoformat(),
            "client_ip": self.client_ip,
            "method": method,
            "url": f"{self.host}{path}",
            "status_code": 500,
            "response_time_ms": int((time.time() - start_time) * 1000),
            "exception": str(exception),
            "user_agent": self.user_agent,
            "referer": random.choice([None, "https://www.google.com", "https://www.bing.com", "https://example.com"]),
            "geo": self.geolocation,
            "request_body": data if data else None
        }
        json_logger.info(json.dumps(log_entry))