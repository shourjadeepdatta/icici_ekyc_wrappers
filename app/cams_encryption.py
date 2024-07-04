import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def CAMSEncryptionCKYC(data):
    algorithm = 'aes-256-cbc'
    varIVBase64 = base64.b64decode("NmZiYmEzOWFhZjFmZTNhZg==")
    varKeyBase64 = base64.b64decode("OGIzOTFhODVhZTc3N2Y4YmFjYTZmZTcyZWRmY2ZjOTE=")

    varIVBuffer = varIVBase64
    varKeyBuffer = varKeyBase64

    varTotalEncrypt = ''

    try:
        # Encrypt data
        cipher = Cipher(algorithms.AES(varKeyBuffer), modes.CBC(varIVBuffer), backend=default_backend())
        encryptor = cipher.encryptor()

        padded_data = json.dumps(data).encode('utf-8')
        # Pad data to be a multiple of 16 bytes
        pad_length = 16 - (len(padded_data) % 16)
        padded_data += bytes([pad_length] * pad_length)

        varDataEncrypt = base64.b64encode(encryptor.update(padded_data) + encryptor.finalize()).decode('utf-8')

        # Create hash of data
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(json.dumps(data).encode('utf-8'))
        varHashString = digest.finalize().hex()

        # Encrypt hash
        cipher = Cipher(algorithms.AES(varKeyBuffer), modes.CBC(varIVBuffer), backend=default_backend())
        encryptor = cipher.encryptor()

        padded_hash = varHashString.encode('utf-8')
        # Pad hash to be a multiple of 16 bytes
        pad_length = 16 - (len(padded_hash) % 16)
        padded_hash += bytes([pad_length] * pad_length)

        varHashEncrypt = base64.b64encode(encryptor.update(padded_hash) + encryptor.finalize()).decode('utf-8')

        varTotalEncrypt = varDataEncrypt + '.' + varHashEncrypt
        return varTotalEncrypt
    except Exception as error:
        print(error)
        return varTotalEncrypt
    finally:
        algorithm = None
        varIVBase64 = None
        varKeyBase64 = None
        varIVBuffer = None
        varKeyBuffer = None

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
