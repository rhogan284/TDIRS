import time
import random
import requests
import logging
import socket
import json
from faker import Faker

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

fake = Faker()

def send_log(message):
    log_entry = json.dumps({"message": message})
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("logstash", 5044))
        s.sendall(log_entry.encode() + b'\n')

def generate_normal_traffic():
    endpoints = ['/', '/products', '/login']
    endpoint = random.choice(endpoints)

    if endpoint == '/login':
        data = {'username': fake.user_name(), 'password': fake.password()}
        response = requests.post(f'http://web:5000{endpoint}', json=data)
    else:
        response = requests.get(f'http://web:5000{endpoint}')

    send_log(
        f"Normal traffic - Method: {response.request.method}, URL: {response.url}, Status: {response.status_code}")


def generate_attack_traffic():
    attack_types = ['sql_injection', 'brute_force', 'xss']
    attack = random.choice(attack_types)

    if attack == 'sql_injection':
        payload = "' OR '1'='1"
        response = requests.get(f'http://web:5000/products?id={payload}')
        send_log(f"Attack traffic - SQL Injection attempt: {response.url}")
    elif attack == 'brute_force':
        for _ in range(5):  # Simulate 5 rapid login attempts
            data = {'username': 'admin', 'password': fake.password()}
            response = requests.post('http://web:5000/login', json=data)
            send_log(f"Attack traffic - Brute force attempt: {data['username']}")
    elif attack == 'xss':
        payload = "<script>alert('XSS')</script>"
        response = requests.get(f'http://web:5000/products?search={payload}')
        send_log(f"Attack traffic - XSS attempt: {response.url}")


if __name__ == '__main__':
    while True:
        if random.random() < 0.9:
            generate_normal_traffic()
        else:
            generate_attack_traffic()
        time.sleep(random.uniform(0.1, 2))