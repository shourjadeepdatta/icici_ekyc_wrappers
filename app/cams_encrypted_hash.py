import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def encrypt_data(data, varIVBase64, varKeyBase64):
    varIVBuffer = base64.b64decode(varIVBase64)
    varKeyBuffer = base64.b64decode(varKeyBase64)

    try:
        cipher = Cipher(algorithms.AES(varKeyBuffer), modes.CBC(varIVBuffer), backend=default_backend())
        encryptor = cipher.encryptor()

        padded_data = data.encode('utf-8')
        pad_length = 16 - (len(padded_data) % 16)
        padded_data += bytes([pad_length] * pad_length)

        encrypted_data = base64.b64encode(encryptor.update(padded_data) + encryptor.finalize()).decode('utf-8')
        return encrypted_data
    except Exception as error:
        print(error)
        return ''

def CAMSEncryptionCKYC(data):
    varIVBase64 = "NmZiYmEzOWFhZjFmZTNhZg=="
    varKeyBase64 = "OGIzOTFhODVhZTc3N2Y4YmFjYTZmZTcyZWRmY2ZjOTE="

    try:
        # Create hash of data
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(json.dumps(data).encode('utf-8'))
        hash_hex = digest.finalize().hex()

        # Encrypt hash hex string
        encrypted_hash = encrypt_data(hash_hex, varIVBase64, varKeyBase64)
        return encrypted_hash
    except Exception as error:
        print(error)
        return ''

# Example payload
payload = {
    "UserID": "ICSDK360_UAT",
    "Password": "bzqUnl1g7At2NlS",
    "DocumentIDRefNo": "2020465465463738_Vk7CESqPwz",
    "Image1": "/9j/4AAQSkZJRgABAQEBLAEsAAD/4QodJRRRXy59Qf........./2Q==",
    "SessionID": "26454520426145353738_BoTVKsp0yz",
    "TimeStamp": "2022-06-15T15:43:02"
}

encrypted_data = CAMSEncryptionCKYC(payload)
print(encrypted_data)
