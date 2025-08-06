# https_server.py
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/', methods=["GET", "POST"])
def hello():
    if request.method == "POST":
        data = request.form.to_dict()
        print("Server received POST data:", data)
        return jsonify({"status": "received", "data": data}), 200
    return "Hello from secure server!"

if __name__ == "__main__":
    app.run(
        host="0.0.0.0", port=9443,
        ssl_context=(
            "ca/certs/server.crt",
            "ca/private/server.key"
        )
    )
