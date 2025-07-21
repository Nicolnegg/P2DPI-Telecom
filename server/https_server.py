# https_server.py
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello from secure server!"

if __name__ == "__main__":
    app.run(
        host="0.0.0.0", port=9443,
        ssl_context=(
            "ca/certs/server.crt",    # cert
            "ca/private/server.key"   # key
        )
    )
