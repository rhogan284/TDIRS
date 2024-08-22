from flask import Flask, request, jsonify
import psycopg2
import os
import logging
from datetime import datetime
import socket
import json

app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database connection
def get_db_connection():
    conn = psycopg2.connect(os.environ['DATABASE_URL'])
    return conn

@app.before_request
def log_request_info():
    log_entry = {
        '@timestamp': datetime.now().isoformat(),
        'remote_addr': request.remote_addr,
        'request_method': request.method,
        'request_uri': request.path,
        'status': 'N/A',
        'http_user_agent': request.headers.get('User-Agent'),
    }
    request.log_entry = log_entry

def send_log_to_logstash(log_entry):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("logstash", 5044))
            s.sendall(json.dumps(log_entry).encode() + b'\n')
    except Exception as e:
        logger.error(f"Failed to send log to Logstash: {e}")

@app.after_request
def log_response_info(response):
    request.log_entry['status'] = response.status_code
    request.log_entry['response_time'] = request.log_entry.get('response_time', 0)
    logger.info(json.dumps(request.log_entry))
    send_log_to_logstash(request.log_entry)
    return response

@app.route('/')
def hello():
    return "Welcome to the E-commerce Platform Simulation!"

@app.route('/products')
def get_products():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM products;')
    products = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([{'id': p[0], 'name': p[1], 'price': p[2]} for p in products])

@app.route('/login', methods=['POST'])
def login():
    # Simulate login (no actual authentication)
    return jsonify({"message": "Login simulation successful"})

@app.route('/cart')
def view_cart():
    return jsonify({"message": "Cart viewed"})

@app.route('/checkout')
def checkout():
    return jsonify({"message": "Checkout process"})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)