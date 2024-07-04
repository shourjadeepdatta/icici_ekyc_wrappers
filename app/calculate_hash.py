import hashlib
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

# Provided data
payload = {
    "UserID": "ICSDK360_UAT",
    "Password": "bzqUnl1g7At2NlS",
    "DocumentIDRefNo": "2020465465463738_Vk7CESqPwz",
    "Image1": "/9j/4AAQSkZJRgABAQEBLAEsAAD/4QodJRRRXy59Qf........./2Q==",
    "SessionID": "26454520426145353738_BoTVKsp0yz",
    "TimeStamp": "2022-06-15T15:43:02"
}

iv = base64.b64decode('NmZiYmEzOWFhZjFmZTNhZg==')
key = base64.b64decode('OGIzOTFhODVhZTc3N2Y4YmFjYTZmZTcyZWRmY2ZjOTE=')

# Convert payload to JSON string
payload_json = json.dumps(payload)

# Compute SHA-256 hash
sha256_hash = hashlib.sha256(payload_json.encode()).hexdigest()

# Convert hash to bytes
hash_bytes = bytes.fromhex(sha256_hash)

# Pad the hash to be a multiple of the AES block size (128 bits / 16 bytes)
padder = PKCS7(algorithms.AES.block_size).padder()
padded_hash = padder.update(hash_bytes) + padder.finalize()

# Encrypt the padded hash
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
encrypted_hash = encryptor.update(padded_hash) + encryptor.finalize()

# Base64 encode the encrypted hash
encrypted_hash_base64 = base64.b64encode(encrypted_hash).decode()

print("Encrypted SHA-256 Hash:", encrypted_hash_base64)
