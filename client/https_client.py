# https_client.py
import requests

response = requests.get(
    "https://server.p2dpi.local:8443/",
    verify="ca/certs/ca.cert.pem"  # Trust the CA
)

print("Response:", response.text)
