from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from ctypes import CDLL, c_char_p, c_int, c_ubyte, create_string_buffer

import struct
import os
import base64
import requests

# Load the PRF shared library (prf.so) and define argument and return types for FKH_hex
# Returns the loaded CDLL object

def load_prf_library():
    """
    Loads the shared PRF library used to compute the intermediate rules.

    Returns:
        CDLL: The loaded shared library object with configured argument/return types for FKH_hex.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    prf_path = os.path.abspath(os.path.join(current_dir, '..', 'shared', 'prf.so'))
    prf = CDLL(prf_path)
    prf.FKH_hex.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_int]
    prf.FKH_hex.restype = c_int
    return prf

# Load the fixed EC point h from file (used in session rule generation)
# Returns h as a hex string

def load_h_fixed():
    """
    Loads the fixed elliptic curve point 'h' used for session-based PRF operations.

    Returns:
        str: The hex-encoded fixed point read from file.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    h_path = os.path.abspath(os.path.join(current_dir, '..', 'shared', 'h_fixed.txt'))
    with open(h_path, 'r') as f:
        return f.read().strip()

# Load a PEM-formatted public key from a specified file path
# Returns the public key object

def load_public_key(path: str):
    """
    Loads an RSA public key from a PEM-formatted file.

    Args:
        path (str): Path to the PEM file containing the public key.

    Returns:
        cryptography.PublicKey: The loaded public key object.
    """
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

# Load and decrypt the shared key kSR using Fernet encryption
# Expects encrypted kSR and the Fernet key to be stored under keys/
# Returns the decrypted kSR string

def load_ksr():
    """
    Loads and decrypts the shared key 'kSR' using Fernet encryption.
    Requires both the encrypted kSR and its encryption key to be present in the 'keys/' directory.

    Returns:
        str: The decrypted shared key kSR.

    Raises:
        ValueError: If either key file is missing.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.join(current_dir, 'keys')
    ksr_path = os.path.join(base_dir, "shared_ksr.key")
    key_path = os.path.join(base_dir, "key_for_ksr.key")

    if not os.path.exists(ksr_path) or not os.path.exists(key_path):
        raise ValueError("Missing kSR or encryption key")

    with open(key_path, "rb") as f:
        key = f.read()
    cipher_suite = Fernet(key)

    with open(ksr_path, "rb") as f:
        encrypted_ksr = f.read()

    return cipher_suite.decrypt(encrypted_ksr).decode()

# Verify an RSA-PSS signature over the input data string using the given public key
# Returns True if signature is valid, False otherwise
# Takes base64-encoded signature and the string data

def verify_signature(data: str, signature_b64: str, public_key) -> bool:
    """
    Verifies the RSA-PSS signature of the provided data using a given public key.

    Args:
        data (str): The original data string to verify.
        signature_b64 (str): Base64-encoded signature string.
        public_key: The loaded RSA public key for verification.

    Returns:
        bool: True if signature is valid, False otherwise.
    """
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def encrypt_tokens(tokens: list, kSR_hex: str, counter: int, prf, h_fixed_hex: str) -> list:
    """
    Encrypt tokens as Ti = H2(c + i, (g^{H1(ti)} * h)^{kSR}).

    Args:
        tokens (list): List of token bytes (ti).
        kSR_hex (str): Shared key kSR as hex string.
        counter (int): Base counter c.
        prf: Loaded PRF library with FKH_hex and H2 functions.
        h_fixed_hex (str): Fixed EC point h as hex string.  --> change

    Returns:
        list of bytes: List of encrypted token bytes Ti.
    """
    BUFFER_SIZE = 200  # buffer size for FKH_hex output
    encrypted_tokens = []

    for i, token_bytes in enumerate(tokens):
        # Token hex uppercase string
        token_hex = token_bytes.hex().upper()

        # Buffer for FKH_hex output
        output_buffer_fk = create_string_buffer(BUFFER_SIZE)

        # Call FKH_hex to compute EC point (g^{H1(ti)} * h)^{kSR}
        res = prf.FKH_hex(
            c_char_p(token_hex.encode()),
            c_char_p(kSR_hex.encode()),
            c_char_p(h_fixed_hex.encode()),
            output_buffer_fk,
            BUFFER_SIZE
        )
        if res != 1:
            raise RuntimeError(f"FKH_hex failed for token {token_hex}")

        point_hex = output_buffer_fk.value.decode()
        point_bytes = bytes.fromhex(point_hex)
        if len(point_bytes) < 16:
            raise RuntimeError(f"EC point bytes too short for token {token_hex}")

        # Use first 16 bytes as key for H2
        h2_key = (c_ubyte * 16).from_buffer_copy(point_bytes[:16])

        # Prepare y = c + i as 16-byte big endian (upper 8 bytes zero, lower 8 bytes counter)
        y_int = counter + i
        y_bytes = struct.pack(">QQ", 0, y_int)
        y_cbytes = (c_ubyte * 16).from_buffer_copy(y_bytes)

        # Buffer for H2 output
        output_h2 = (c_ubyte * 16)()

        # Call H2 function: H2(y_bytes, 16, h2_key, output_h2)
        success = prf.H2(y_cbytes, 16, h2_key, output_h2)
        if success != 1:
            raise RuntimeError(f"H2 encryption failed for token {token_hex}")

        encrypted_tokens.append(bytes(output_h2))

    return encrypted_tokens

def send_alert_to_middlebox(alert_data):
    """
    Sends alert JSON to Middlebox indicating a possible attack.
    """
    try:
        mb_alert_url = "http://localhost:9999/validation"
        response = requests.post(mb_alert_url, json=alert_data, timeout=3)
        print(f"[Receiver HTTPS] Alert sent to Middlebox: {response.status_code}")
    except Exception as e:
        print(f"[Receiver HTTPS] Failed to send alert to Middlebox: {e}")