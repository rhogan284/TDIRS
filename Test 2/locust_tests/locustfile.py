from locust import HttpUser, task, between
from locust.contrib.fasthttp import FastHttpUser
import random
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

class WebsiteUser(FastHttpUser):
    wait_time = between(1, 5)

    def on_start(self):
        self.login()

    def login(self):
        self.client.post("/login", json={"username": f"user_{random.randint(1, 1000)}", "password": "password"})

    @task(10)
    def index_page(self):
        self.client.get("/")

    @task(5)
    def view_products(self):
        self.client.get("/products")

    @task(3)
    def view_product_details(self):
        product_id = random.randint(1, 10)
        self.client.get(f"/products/{product_id}")

    @task(2)
    def add_to_cart(self):
        product_id = random.randint(1, 10)
        self.client.post("/cart", json={"product_id": product_id, "quantity": random.randint(1, 3)})

    @task(1)
    def view_cart(self):
        self.client.get("/cart")

    @task(1)
    def checkout(self):
        self.client.post("/checkout", json={
            "shipping_address": "123 Test St, Test City, 12345",
            "payment_method": "credit_card"
        })

    @task(1)
    def search(self):
        search_terms = ["laptop", "smartphone", "headphones", "tablet", "camera"]
        term = random.choice(search_terms)
        self.client.get(f"/search?q={term}")

    def on_request_success(self, request_type, name, response_time, response_length, response):
        log_entry = {
            "@timestamp": self.environment.runner.time(),
            "request_type": request_type,
            "path": name,
            "response_time": response_time,
            "status_code": response.status_code,
            "response_length": response_length,
            "user_agent": self.client.headers.get("User-Agent", "")
        }
        logger.info(json.dumps(log_entry))