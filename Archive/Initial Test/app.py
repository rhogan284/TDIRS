from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
import logging
from prometheus_client import Counter, Histogram, generate_latest, start_http_server
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from prometheus_client import make_wsgi_app

app = Flask(__name__)
app.secret_key = "ymFQm5wlzg"

logging.basicConfig(filename='access.log', level=logging.INFO)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Dummy user database
users = {'user1': 'password1', 'user2': 'password2'}

# Prometheus metrics
REQUEST_COUNT = Counter('http_request_count', 'Total number of HTTP requests', ['method', 'endpoint'])
LOGIN_FAILURE_COUNT = Counter('login_failure_count', 'Number of failed login attempts')
REQUEST_LATENCY = Histogram('http_request_latency_seconds', 'Request latency in seconds', ['endpoint'])


class User(UserMixin):
    def __init__(self, username):
        self.id = username


@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None


@app.before_request
def before_request():
    # Increment the request count before each request
    REQUEST_COUNT.labels(method=request.method, endpoint=request.path).inc()


@app.route('/')
def index():
    with REQUEST_LATENCY.labels(endpoint='/').time():
        return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    with REQUEST_LATENCY.labels(endpoint='/login').time():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            # Log the login attempt
            logging.info(f"Login attempt: {username}, IP: {request.remote_addr}")

            if username in users and users[username] == password:
                user = User(username)
                login_user(user)
                logging.info(f"Successful login: {username}, IP: {request.remote_addr}")
                return redirect(url_for('protected'))
            else:
                LOGIN_FAILURE_COUNT.inc()
                print("LOGIN_FAILURE_COUNT incremented")  # Debug log to ensure it's called
                print(LOGIN_FAILURE_COUNT)
                logging.info(f"Failed login: {username}, IP: {request.remote_addr}")
                flash('Invalid credentials!')

        return render_template('login.html')


@app.route('/protected')
@login_required
def protected():
    with REQUEST_LATENCY.labels(endpoint='/protected').time():
        return 'Logged in successfully!'


@app.route('/logout')
@login_required
def logout():
    with REQUEST_LATENCY.labels(endpoint='/logout').time():
        logout_user()
        return redirect(url_for('index'))


# Expose Prometheus metrics
app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {
    '/metrics': make_wsgi_app()
})

if __name__ == '__main__':
    # Start Prometheus metrics server on port 8000
    start_http_server(9001)
    app.run(port=5001, debug=True, use_reloader=False)

