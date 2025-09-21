# server.py
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/user", methods=["POST"])
def receive_user():
    # Deserialize JSON payload
    data = request.get_json()
    
    # Process the data
    name = data.get("name")
    age = data.get("age")
    is_admin = data.get("is_admin")

    print(f"Received user: {name}, Age: {age}, Admin: {is_admin}")

    # Respond back
    return jsonify({"status": "success", "message": f"Hello {name}, your data was received!"})

if __name__ == "__main__":
    app.run(debug=True)
