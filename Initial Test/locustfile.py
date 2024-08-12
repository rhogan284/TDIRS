from locust import FastHttpUser, between, task

class WebsiteUser(FastHttpUser):
    wait_time = between(1, 5)
    host = "http://localhost:5000"

    @task(1)
    def login(self):
        response = self.client.post("/login", {"username": "user1", "password": "password1"})
        if response.status_code == 200:
            print("Login successful")
        else:
            print("Login failed")

    @task(2)
    def access_protected(self):
        self.client.get("/protected")

