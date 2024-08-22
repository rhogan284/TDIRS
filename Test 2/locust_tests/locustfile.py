from locust import HttpUser, task, between


class WebsiteUser(HttpUser):
    wait_time = between(1, 5)

    @task(2)
    def index_page(self):
        self.client.get("/")

    @task(1)
    def view_products(self):
        self.client.get("/products")

    @task(1)
    def view_cart(self):
        self.client.get("/cart")

    @task(1)
    def checkout(self):
        self.client.get("/checkout")

    @task(1)
    def login(self):
        self.client.post("/login", json={"username": "testuser", "password": "testpass"})