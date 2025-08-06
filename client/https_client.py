# https_client.py
import requests

data = {
    "username": "alice",
    "password": "secure123"
}

response = requests.post(
    "https://sender.p2dpi.local:8443/",
    data=data,
    verify="ca/certs/ca.cert.pem"  # Trust the CA
)

print("POST response:", response.text)
