import json
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

payload = {
    "UserID": "ICSDK360_UAT",
    "Password": "bzqUnl1g7At2NlS",
    "DocumentIDRefNo": "2020465465463738_Vk7CESqPwz",
    "Image1": "/9j/4AAQSkZJRgABAQEBLAEsAAD/4QodJRRRXy59Qf........./2Q==",
    "SessionID": "26454520426145353738_BoTVKsp0yz",
    "TimeStamp": "2022-06-15T15:43:02"
}

# Convert payload to JSON string
payload_json = json.dumps(payload)

# Step 2: Compute SHA-256 hash of the JSON payload
sha256_hash = hashlib.sha256(payload_json.encode()).hexdigest()

print("SHA-256 Hash (Hexadecimal):", sha256_hash)

# Step 3: AES-256 encryption of data (payload_json)
# Initialization Vector (IV) and AES Key provided by CAMS (base64 encoded)
iv_base64 = 'NmZiYmEzOWFhZjFmZTNhZg=='
key_base64 = 'OGIzOTFhODVhZTc3N2Y4YmFjYTZmZTcyZWRmY2ZjOTE='

# Decode IV and AES key from base64
iv = base64.b64decode(iv_base64)
key = base64.b64decode(key_base64)

# Convert payload JSON to bytes
data_bytes = payload_json.encode()

# Pad the data to be a multiple of the AES block size (128 bits / 16 bytes) using PKCS7
padder = padding.PKCS7(algorithms.AES.block_size).padder()
padded_data = padder.update(data_bytes) + padder.finalize()

# Encrypt using AES-256 in CBC mode
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

# Base64 encode the encrypted data
encrypted_data_base64 = base64.b64encode(encrypted_data).decode('utf-8')

print("Encrypted Data (Base64):", encrypted_data_base64)

# Step 4: AES-256 encryption of SHA-256 hash (sha256_hash)
# Convert SHA-256 hash to bytes
hash_bytes = bytes.fromhex(sha256_hash)

# Pad the hash to be a multiple of the AES block size (128 bits / 16 bytes) using PKCS7
padder = padding.PKCS7(algorithms.AES.block_size).padder()
padded_hash = padder.update(hash_bytes) + padder.finalize()

# Encrypt using AES-256 in CBC mode
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
encrypted_hash = encryptor.update(padded_hash) + encryptor.finalize()

# Base64 encode the encrypted hash
encrypted_hash_base64 = base64.b64encode(encrypted_hash).decode('utf-8')

print("Encrypted Hash (Base64):", encrypted_hash_base64)

# Step 5: Concatenate DATA and HASH with "." separator
final_result = f"{encrypted_data_base64}.{encrypted_hash_base64}"

print("Final Result:", final_result)