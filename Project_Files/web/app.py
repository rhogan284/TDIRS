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

REDIS_KEY_PREFIX = os.environ.get('REDIS_KEY_PREFIX', 'threat_responder:')
REDIS_URL = os.environ.get('REDIS_URL', 'redis://redis:6379/0')
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://user:password@db:5432/ecommerce')
BLOCKED_IPS_KEY = f"{REDIS_KEY_PREFIX}blocked_ips"


# Initialize Redis client with retry logic
def get_redis_client():
    for _ in range(5):  # Try 5 times
        try:
            client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
            client.ping()  # Test the connection
            return client
        except redis.exceptions.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            time.sleep(5)  # Wait for 5 seconds before retrying
    logger.error("Failed to connect to Redis after multiple attempts")
    return None


redis_client = get_redis_client()


# Initialize PostgreSQL connection with retry logic
def get_db_connection():
    for _ in range(5):  # Try 5 times
        try:
            conn = psycopg2.connect(DATABASE_URL)
            conn.autocommit = True
            return conn
        except psycopg2.OperationalError as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            time.sleep(5)  # Wait for 5 seconds before retrying
    logger.error("Failed to connect to PostgreSQL after multiple attempts")
    return None


def is_ip_blocked(ip):
    if redis_client is None:
        logger.error("Redis client is not available")
        return False
    try:
        is_blocked = redis_client.sismember(BLOCKED_IPS_KEY, ip)
        logger.info(f"Checking if IP {ip} is blocked. Result: {is_blocked}")
        return is_blocked
    except redis.exceptions.RedisError as e:
        logger.error(f"Error checking if IP is blocked: {e}")
        return False


def block_ip(ip):
    if redis_client is None:
        logger.error("Redis client is not available")
        return
    try:
        redis_client.sadd(BLOCKED_IPS_KEY, ip)
        redis_client.expire(BLOCKED_IPS_KEY, 3600)  # Block for 1 hour
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


def detect_threat(request):
    # Implement basic threat detection logic
    path = request.path
    args = request.args
    body = request.get_json(silent=True)

    # Check for common attack patterns
    if any(pattern in path for pattern in ['../', '..\\', 'etc/passwd', 'win.ini']):
        return 'path_traversal'
    if any(pattern in str(args) for pattern in ["'", '"', ';', '--', '1=1']):
        return 'sql_injection'
    if body and '<script>' in str(body):
        return 'xss'

    return None


@app.after_request
def detect_and_block_threats(response):
    client_ip = get_client_ip()
    threat = detect_threat(request)
    if threat:
        logger.warning(f"Detected {threat} threat from IP: {client_ip}")
        block_ip(client_ip)
    return response


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
    # Simulate login (no actual authentication)
    return jsonify({"message": "Login simulation successful"})


@app.route('/cart', methods=['GET', 'POST'])
def cart():
    if request.method == 'POST':
        # Simulate adding to cart
        return jsonify({"message": "Item added to cart"})
    else:
        # Simulate viewing cart
        return jsonify({"message": "Cart viewed"})


@app.route('/checkout', methods=['POST'])
def checkout():
    return jsonify({"message": "Checkout process completed"})


@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Simulate search results
    return jsonify({"message": f"Search results for: {query}"})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
