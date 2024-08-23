import random
import json
import logging
import time
import uuid
from locust import HttpUser, task, between
from locust.contrib.fasthttp import FastHttpUser
from datetime import datetime

# Use the same logging setup as in your main locustfile.py
json_logger = logging.getLogger('json_logger')
json_logger.setLevel(logging.INFO)
json_handler = logging.FileHandler('/mnt/logs/threat_locust_json.log')
json_handler.setFormatter(logging.Formatter('%(message)s'))
json_logger.addHandler(json_handler)

class MaliciousUser(FastHttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        self.user_id = str(uuid.uuid4())
        self.session_id = str(uuid.uuid4())
        self.client_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        self.user_agent = 'MaliciousBot/1.0'
        self.geolocation = {"country": "Unknown", "city": "Unknown", "timezone": "UTC"}

    @task(1)
    def sql_injection_attempt(self):
        payload = "' OR '1'='1"
        self._log_request("GET", f"/products?id={payload}", None, "SQL Injection Attempt")

    @task(2)
    def xss_attempt(self):
        payload = "<script>alert('XSS')</script>"
        self._log_request("POST", "/search", {"q": payload}, "XSS Attempt")

    @task(3)
    def brute_force_login(self):
        username = f"admin{random.randint(1, 1000)}"
        password = f"password{random.randint(1, 1000)}"
        self._log_request("POST", "/login", {"username": username, "password": password}, "Brute Force Login Attempt")

    @task(1)
    def path_traversal_attempt(self):
        self._log_request("GET", "/static/../../../etc/passwd", None, "Path Traversal Attempt")

    @task(2)
    def ddos_simulation(self):
        for _ in range(10):
            self._log_request("GET", "/", None, "DDoS Simulation")

    def _log_request(self, method, path, data, attack_type):
        start_time = time.time()
        try:
            if method == "GET":
                response = self.client.get(path)
            elif method == "POST":
                response = self.client.post(path, json=data)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            self._log_response(method, path, response, start_time, attack_type)
        except Exception as e:
            self._log_exception(method, path, e, start_time, attack_type)

    def _log_response(self, method, path, response, start_time, attack_type):
        log_entry = {
            "timestamp": int(time.time() * 1000),
            "user_id": self.user_id,
            "session_id": self.session_id,
            "client_ip": self.client_ip,
            "method": method,
            "path": path,
            "attack_type": attack_type,
            "response_time": int((time.time() - start_time) * 1000),
            "status": response.status_code,
            "bytes_sent": len(response.request.body) if response.request.body else 0,
            "bytes_received": len(response.content),
            "user_agent": self.user_agent,
            "country": self.geolocation['country'],
            "city": self.geolocation['city'],
            "timezone": self.geolocation['timezone'],
            "local_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        json_logger.info(json.dumps(log_entry))

    def _log_exception(self, method, path, exception, start_time, attack_type):
        log_entry = {
            "timestamp": int(time.time() * 1000),
            "user_id": self.user_id,
            "session_id": self.session_id,
            "client_ip": self.client_ip,
            "method": method,
            "path": path,
            "attack_type": attack_type,
            "response_time": int((time.time() - start_time) * 1000),
            "status": 500,
            "exception": str(exception),
            "user_agent": self.user_agent,
            "country": self.geolocation['country'],
            "city": self.geolocation['city'],
            "timezone": self.geolocation['timezone'],
            "local_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        json_logger.info(json.dumps(log_entry))