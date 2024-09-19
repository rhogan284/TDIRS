import time
import random
import requests
import json
import socket
from faker import Faker

fake = Faker()


def generate_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"


def generate_log_entry():
    timestamp = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime()) + "Z"
    ip = generate_ip()
    user_agent = fake.user_agent()
    method = random.choice(['GET', 'POST', 'PUT', 'DELETE'])
    path = random.choice(['/', '/products', '/cart', '/checkout', '/login', '/register', '/api/v1/products'])
    status = random.choice([200, 201, 204, 301, 302, 400, 401, 403, 404, 500])
    response_time = round(random.uniform(0.1, 2.0), 3)

    log_entry = {
        '@timestamp': timestamp,
        'remote_addr': ip,
        'request_method': method,
        'request_uri': path,
        'status': status,
        'http_user_agent': user_agent,
        'response_time': response_time
    }

    if random.random() < 0.05:
        if random.random() < 0.5:
            log_entry['request_uri'] += f"?id=1 OR 1=1"
        else:
            log_entry['request_uri'] += f"<script>alert('XSS')</script>"
        log_entry['status'] = 400

    return json.dumps(log_entry)


def send_log(log_entry):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("logstash", 5044))
        s.sendall(log_entry.encode() + b'\n')


if __name__ == '__main__':
    while True:
        log = generate_log_entry()
        send_log(log)
        time.sleep(random.uniform(0.1, 1.0))