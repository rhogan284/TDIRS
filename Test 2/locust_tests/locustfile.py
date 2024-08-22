from locust import HttpUser, task, between
from locust.contrib.fasthttp import FastHttpUser
import random
import json
import logging
import time
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

class WebsiteUser(FastHttpUser):
    wait_time = between(1, 5)

    def on_start(self):
        self.user_id = str(uuid.uuid4())
        self.session_id = str(uuid.uuid4())
        self.login()

    def login(self):
        self._log_request("POST", "/login", {"username": f"user_{self.user_id}", "password": "password"})

    @task(10)
    def index_page(self):
        self._log_request("GET", "/")

    @task(5)
    def view_products(self):
        self._log_request("GET", "/products")

    @task(3)
    def view_product_details(self):
        product_id = random.randint(1, 10)
        self._log_request("GET", f"/products/{product_id}")

    @task(2)
    def add_to_cart(self):
        product_id = random.randint(1, 10)
        self._log_request("POST", "/cart", {"product_id": product_id, "quantity": random.randint(1, 3)})

    @task(1)
    def view_cart(self):
        self._log_request("GET", "/cart")

    @task(1)
    def checkout(self):
        self._log_request("POST", "/checkout", {
            "shipping_address": "123 Test St, Test City, 12345",
            "payment_method": "credit_card"
        })

    @task(1)
    def search(self):
        search_terms = ["laptop", "smartphone", "headphones", "tablet", "camera"]
        term = random.choice(search_terms)
        self._log_request("GET", f"/search?q={term}")

    def _log_request(self, method, path, data=None):
        start_time = time.time()
        try:
            if method == "GET":
                response = self.client.get(path)
            elif method == "POST":
                response = self.client.post(path, json=data)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            self._log_response(method, path, response, start_time)
        except Exception as e:
            self._log_exception(method, path, e, start_time)

    def _log_response(self, method, path, response, start_time):
        log_entry = {
            "timestamp": int(time.time() * 1000),
            "user_id": self.user_id,
            "session_id": self.session_id,
            "client_ip": f"192.168.0.{random.randint(1, 255)}",
            "method": method,
            "path": path,
            "response_time": int((time.time() - start_time) * 1000),
            "status": response.status_code,
            "bytes_sent": len(response.request.body) if response.request.body else 0,
            "bytes_received": len(response.content),
            "user_agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(80, 90)}.0.{random.randint(1000, 9999)}.0 Safari/537.36"
        }
        logger.info(json.dumps(log_entry))

    def _log_exception(self, method, path, exception, start_time):
        log_entry = {
            "timestamp": int(time.time() * 1000),
            "user_id": self.user_id,
            "session_id": self.session_id,
            "client_ip": f"192.168.0.{random.randint(1, 255)}",
            "method": method,
            "path": path,
            "response_time": int((time.time() - start_time) * 1000),
            "status": 500,
            "exception": str(exception),
            "user_agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(80, 90)}.0.{random.randint(1000, 9999)}.0 Safari/537.36"
        }
        logger.info(json.dumps(log_entry))