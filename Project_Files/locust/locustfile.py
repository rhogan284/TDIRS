import random
import json
import logging
import time
import uuid
from locust import HttpUser, task, between
from locust.contrib.fasthttp import FastHttpUser
from datetime import datetime

logging.getLogger('locust.user.task').disabled = True
logging.getLogger('locust.user.wait_time').disabled = True

json_logger = logging.getLogger('json_logger')
json_logger.setLevel(logging.INFO)
json_handler = logging.FileHandler('/mnt/logs/locust_json.log')
json_handler.setFormatter(logging.Formatter('%(message)s'))
json_logger.addHandler(json_handler)

standard_logger = logging.getLogger('locust')

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
]

GEOLOCATIONS = [
    {"country": "United States", "city": "New York", "timezone": "America/New_York"},
    {"country": "United Kingdom", "city": "London", "timezone": "Europe/London"},
    {"country": "Japan", "city": "Tokyo", "timezone": "Asia/Tokyo"},
    {"country": "Australia", "city": "Sydney", "timezone": "Australia/Sydney"},
    {"country": "Germany", "city": "Berlin", "timezone": "Europe/Berlin"}
]

REFERRERS = [
    "https://www.google.com",
    "https://www.bing.com",
    "https://www.facebook.com",
    "https://www.twitter.com",
    "https://www.instagram.com",
    None
]

class WebsiteUser(FastHttpUser):
    wait_time = between(5, 15)

    def on_start(self):
        self.user_id = str(uuid.uuid4())
        self.session_id = str(uuid.uuid4())
        self.client_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        self.user_agent = random.choice(USER_AGENTS)
        self.geolocation = random.choice(GEOLOCATIONS)
        self.session_start_time = time.time()
        self.products_viewed = set()
        self.cart_items = []
        self.login()

    def on_stop(self):
        self.logout()

    def login(self):
        self._log_request("POST", "/login", {"username": f"user_{self.user_id}", "password": "password"}, "Login Page")

    def logout(self):
        self._log_request("POST", "/logout", None, "Logout")

    @task(10)
    def index_page(self):
        self._check_and_renew_session()
        self._log_request("GET", "/", None, "Home Page")

    @task(5)
    def view_products(self):
        self._check_and_renew_session()
        self._log_request("GET", "/products", None, "Products List Page")

    @task(3)
    def view_product_details(self):
        self._check_and_renew_session()
        product_id = random.randint(1, 100)
        self.products_viewed.add(product_id)
        self._log_request("GET", f"/products/{product_id}", None, f"Product Detail Page (ID: {product_id})")

    @task(2)
    def add_to_cart(self):
        self._check_and_renew_session()
        if self.products_viewed:
            product_id = random.choice(list(self.products_viewed))
            quantity = random.randint(1, 3)
            self.cart_items.append({"product_id": product_id, "quantity": quantity})
            self._log_request("POST", "/cart", {"product_id": product_id, "quantity": quantity}, "Add to Cart")

    @task(1)
    def view_cart(self):
        self._check_and_renew_session()
        self._log_request("GET", "/cart", None, "Shopping Cart Page")

    @task(1)
    def checkout(self):
        self._check_and_renew_session()
        if self.cart_items:
            self._log_request("POST", "/checkout", {
                "shipping_address": "123 Test St, Test City, 12345",
                "payment_method": "credit_card",
                "items": self.cart_items
            }, "Checkout Page")
            self.cart_items = []

    @task(1)
    def search(self):
        self._check_and_renew_session()
        search_terms = ["laptop", "smartphone", "headphones", "tablet", "camera"]
        term = random.choice(search_terms)
        self._log_request("GET", f"/search?q={term}", None, f"Search Results Page (Query: {term})")

    def _check_and_renew_session(self):
        current_time = time.time()
        if current_time - self.session_start_time > 1800:
            self.session_id = str(uuid.uuid4())
            self.session_start_time = current_time

    def _log_request(self, method, path, data, page_description):
        start_time = time.time()
        try:
            if random.random() < 0.01:
                raise Exception("Random error occurred")

            if method == "GET":
                response = self.client.get(path)
            elif method == "POST":
                response = self.client.post(path, json=data)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            self._log_response(method, path, response, start_time, page_description)
        except Exception as e:
            self._log_exception(method, path, e, start_time, page_description)

    def _log_response(self, method, path, response, start_time, page_description):
        log_entry = {
            "timestamp": int(time.time() * 1000),
            "user_id": self.user_id,
            "session_id": self.session_id,
            "client_ip": self.client_ip,
            "method": method,
            "path": path,
            "page": page_description,
            "response_time": int((time.time() - start_time) * 1000),
            "status": response.status_code,
            "bytes_sent": len(response.request.body) if response.request.body else 0,
            "bytes_received": len(response.content),
            "user_agent": self.user_agent,
            "country": self.geolocation['country'],
            "city": self.geolocation['city'],
            "timezone": self.geolocation['timezone'],
            "referrer": random.choice(REFERRERS),
            "local_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        json_logger.info(json.dumps(log_entry))

    def _log_exception(self, method, path, exception, start_time, page_description):
        log_entry = {
            "timestamp": int(time.time() * 1000),
            "user_id": self.user_id,
            "session_id": self.session_id,
            "client_ip": self.client_ip,
            "method": method,
            "path": path,
            "page": page_description,
            "response_time": int((time.time() - start_time) * 1000),
            "status": 500,
            "exception": str(exception),
            "user_agent": self.user_agent,
            "country": self.geolocation['country'],
            "city": self.geolocation['city'],
            "timezone": self.geolocation['timezone'],
            "referrer": random.choice(REFERRERS),
            "local_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        json_logger.info(json.dumps(log_entry))