

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from ctypes import CDLL, c_char_p, c_int, create_string_buffer


import os
import base64
import logging

BUFFER_SIZE = 200
TOKEN_WINDOW_SIZE = 8

# === Load PRF library (FKH_hex) from shared C code ===
current_dir = os.path.dirname(os.path.abspath(__file__))
prf_path = os.path.abspath(os.path.join(current_dir, '..', 'shared', 'prf.so'))
prf = CDLL(prf_path)

prf.FKH_hex.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
prf.FKH_hex.restype = c_int



def extract_tokens_sliding_window(payload: bytes, window_size=TOKEN_WINDOW_SIZE):
    """
    Extracts tokens from a byte payload using a sliding window algorithm.
    Each token is a slice of 'window_size' bytes, sliding by one byte each step.
    Args:
        payload (bytes): The input byte stream to tokenize.
        window_size (int): The fixed size of each token window (default 8).

    Returns:
        List[bytes]: A list of byte tokens extracted from the payload.
    """
    if len(payload) < window_size:
        return []
    return [payload[i:i+window_size] for i in range(len(payload) - window_size + 1)]


def encrypt_tokens(tokens, kSR_hex, counter):
    """
    Encrypts each token using the P2DPI encryption scheme.

    For each token t_i, it computes:
        T_i = H2(counter + i, (g^{H1(t_i)} h)^{kSR})

    Here, the cryptographic operation is done by calling
    the external C library function 'FKH_hex' via ctypes.

    Args:
        tokens (List[bytes]): List of token byte strings extracted from the traffic.
        kSR_hex (str): The session key 'kSR' as a hex string.
        counter (int): A random counter used to avoid pattern leakage.

    Returns:
        List[str]: List of encrypted token hex strings T_i.
    """
    encrypted_tokens = []
    output_buffer = create_string_buffer(BUFFER_SIZE)  # buffer to receive output from C function

    for i, token_bytes in enumerate(tokens):
        # Convert token bytes to uppercase hex string for the C function
        token_hex = token_bytes.hex().upper()

        # Call the C library function to perform the key-homomorphic encryption
        # The C function signature:
        # int FKH_hex(char* token_hex, char* kSR_hex, char* output, int out_len);
        res = prf.FKH_hex(token_hex.encode(), kSR_hex.encode(), output_buffer, BUFFER_SIZE)
        if res != 1:
            raise RuntimeError(f"Encryption failed for token {token_hex}")

        # Decode the output buffer value (encrypted token) as a UTF-8 string
        encrypted_tokens.append(output_buffer.value.decode())

    return encrypted_tokens

# === Load RG's public key ===
def load_public_key(path: str):
    try:
        with open(path, 'rb') as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())
    except Exception as e:
        logging.error(f"Failed to load public key from {path}: {e}")
        raise

# === Verify RSA-PSS signature ===
def verify_signature(data: str, signature_b64: str, public_key) -> bool:
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

def compute_intermediate_rules_hex(rules_hex, kSR_hex):
    results = []
    output_buffer = create_string_buffer(BUFFER_SIZE)
    for r in rules_hex:
        res = prf.FKH_hex(r.encode(), kSR_hex.encode(), output_buffer, BUFFER_SIZE)
        if res != 1:
            logging.error(f"FKH_hex failed for input: {r}")
            raise RuntimeError(f"FKH_hex failed for input: {r}")
        results.append(output_buffer.value.decode())
    return results
    
# === Path to stored kSR key file ===
ksr_path = os.path.abspath(os.path.join(current_dir, "keys", "shared_ksr.key"))

def load_ksr_from_file():
    if not os.path.exists(ksr_path):
        raise FileNotFoundError(f"kSR key file not found: {ksr_path}")
    with open(ksr_path, "r") as f:
        return f.read().strip()