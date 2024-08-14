from flask import Flask, request, jsonify
import psycopg2
import os
import logging

app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database connection
def get_db_connection():
    conn = psycopg2.connect(os.environ['DATABASE_URL'])
    return conn

@app.route('/')
def hello():
    logger.info("Received request for root endpoint")
    return "Welcome to the E-commerce Platform Simulation!"

@app.route('/products', methods=['GET'])
def get_products():
    logger.info("Received request for products")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM products;')
    products = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([{'id': p[0], 'name': p[1], 'price': p[2]} for p in products])

@app.route('/login', methods=['POST'])
def login():
    logger.info(f"Login attempt for user: {request.json.get('username')}")
    # Simulate login (no actual authentication)
    return jsonify({"message": "Login simulation successful"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)