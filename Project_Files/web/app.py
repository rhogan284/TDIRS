from flask import Flask, request, jsonify
import psycopg2
import os

app = Flask(__name__)

def get_db_connection():
    conn = psycopg2.connect(os.environ['DATABASE_URL'])
    return conn

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