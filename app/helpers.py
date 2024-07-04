import xml.etree.ElementTree as ET
import hashlib
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

def dict_to_xml(tag, d):
    elem = ET.Element(tag)
    for key, val in d.items():
        if isinstance(val, dict):
            child = dict_to_xml(key, val)
            elem.append(child)
        else:
            child = ET.Element(key)
            child.text = str(val)
            elem.append(child)
    return elem


def calculate_hash(payload):  

    iv = base64.b64decode('NmZiYmEzOWFhZjFmZTNhZg==')
    key = base64.b64decode('OGIzOTFhODVhZTc3N2Y4YmFjYTZmZTcyZWRmY2ZjOTE=')

    payload_json = json.dumps(payload)
    # Convert payload to JSON string
    sha256_hash = hashlib.sha256(payload_json.encode()).hexdigest()

    print("sha256_hash ->>", sha256_hash)

    # Convert hash to bytes
    hash_bytes = bytes.fromhex(sha256_hash)
    # hash_bytes = sha256_hash

    # Provided IV and AES key
    iv = base64.b64decode('NmZiYmEzOWFhZjFmZTNhZg==')
    print("iv->>",iv)
    key = base64.b64decode('OGIzOTFhODVhZTc3N2Y4YmFjYTZmZTcyZWRmY2ZjOTE=')
    print("key->>>",key)

    # Pad the hash to be a multiple of the AES block size (128 bits / 16 bytes) using PKCS7
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_hash = padder.update(hash_bytes) + padder.finalize()

    # Create a CBC mode cipher with the provided key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded hash using CBC mode
    encrypted_hash = encryptor.update(padded_hash) + encryptor.finalize()

    # Base64 encode the encrypted hash
    encrypted_hash_base64 = base64.b64encode(encrypted_hash).decode()

    print("Encrypted SHA-256 Hash in Base64 (CBC mode with PKCS7 padding):", encrypted_hash_base64)

    return encrypted_hash_base64


def encrypt_payload(payload):

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

    return encrypted_base64