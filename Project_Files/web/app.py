from flask import Flask, request, jsonify
import psycopg2
import os
import redis
import logging
from functools import lru_cache
import time

app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

REDIS_URL = os.environ.get('REDIS_URL', 'redis://redis:6379/0')
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://user:password@db:5432/ecommerce')
BLOCKED_IPS_KEY = "threat_responder:blocked_ips"

def get_redis_client():
    try:
        client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        client.ping()
        logger.info(f"Successfully connected to Redis at {REDIS_URL}")
        logger.info(f"Using blocked IPs key: {BLOCKED_IPS_KEY}")
        return client
    except redis.exceptions.ConnectionError as e:
        logger.error(f"Failed to connect to Redis: {e}")
        return None


redis_client = get_redis_client()

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    return conn

def is_ip_blocked(ip):
    try:
        is_blocked = redis_client.sismember(BLOCKED_IPS_KEY, ip)
        logger.info(f"Checking if IP {ip} is blocked. Result: {is_blocked}")
        all_members = redis_client.smembers(BLOCKED_IPS_KEY)
        logger.info(f"All blocked IPs: {all_members}")
        return is_blocked
    except redis.exceptions.RedisError as e:
        logger.error(f"Error checking if IP is blocked: {e}")
        return False

def block_ip(ip):
    try:
        redis_client.sadd(BLOCKED_IPS_KEY, ip)
        redis_client.expire(BLOCKED_IPS_KEY, 3600)
        logger.info(f"Blocked IP: {ip}")
    except redis.exceptions.RedisError as e:
        logger.error(f"Error blocking IP: {e}")

def get_client_ip():
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.remote_addr
    return ip

@app.before_request
def check_if_blocked():
    client_ip = get_client_ip()
    logger.info(f"Received request from IP: {client_ip}")
    logger.info(f"Headers: {request.headers}")
    if is_ip_blocked(client_ip):
        logger.warning(f"Blocked request from IP: {client_ip}")
        return jsonify({"error": "Access denied"}), 403
    logger.info(f"Allowed request from IP: {client_ip}")

@app.route('/')
def hello():
    return "Welcome to the E-commerce Platform Simulation!"


@app.route('/products')
def get_products():
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection error"}), 500
    try:
        with conn.cursor() as cur:
            cur.execute('SELECT * FROM products;')
            products = cur.fetchall()
        return jsonify([{'id': p[0], 'name': p[1], 'price': p[2]} for p in products])
    except psycopg2.Error as e:
        logger.error(f"Database error: {e}")
        return jsonify({"error": "Database error"}), 500
    finally:
        conn.close()


@app.route('/products/<int:product_id>')
def get_product(product_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM products WHERE id = %s;', (product_id,))
    product = cur.fetchone()
    cur.close()
    conn.close()
    if product:
        return jsonify({'id': product[0], 'name': product[1], 'price': product[2]})
    return jsonify({"error": "Product not found"}), 404


@app.route('/login', methods=['POST'])
def login():
    return jsonify({"message": "Login simulation successful"})


@app.route('/cart', methods=['GET', 'POST'])
def cart():
    if request.method == 'POST':
        return jsonify({"message": "Item added to cart"})
    else:
        return jsonify({"message": "Cart viewed"})


@app.route('/checkout', methods=['POST'])
def checkout():
    return jsonify({"message": "Checkout process completed"})


@app.route('/search')
def search():
    query = request.args.get('q', '')
    return jsonify({"message": f"Search results for: {query}"})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
