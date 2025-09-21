# client.py
import json
import requests

# Data to send
user_data = {
    "name": "Ali",
    "age": 25,
    "is_admin": True
}

# Serialize to JSON
json_payload = json.dumps(user_data)

# Send to server
response = requests.post("http://localhost:5000/api/user", data=json_payload, headers={"Content-Type": "application/json"})

print("Server Response:", response.text)
