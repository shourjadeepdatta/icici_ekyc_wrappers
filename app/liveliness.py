import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

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

# Pad the payload
padder = PKCS7(algorithms.AES.block_size).padder()
padded_data = padder.update(payload_json.encode()) + padder.finalize()

# Encrypt the payload
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

# Base64 encode the encrypted data
encrypted_base64 = base64.b64encode(encrypted_data).decode()

print("Encrypted Payload:", encrypted_base64)