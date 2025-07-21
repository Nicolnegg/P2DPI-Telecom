import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

private_key_dir = os.path.join(os.path.dirname(__file__), 'keys')
shared_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'shared', 'keys'))

private_key_path = os.path.join(private_key_dir, 'rg_private_key.pem')
public_key_path = os.path.join(shared_dir, 'rg_public_key.pem')

# Generar clave privada RSA 2048 bits
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Guardar clave privada (sin cifrado)
with open(private_key_path, "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Guardar clave pública en shared/keys
with open(public_key_path, "wb") as f:
    f.write(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("[RG] Private key saved in:", private_key_path)
print("[RG] Public key saved in:", public_key_path)
