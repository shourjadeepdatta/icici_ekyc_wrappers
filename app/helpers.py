import xml.etree.ElementTree as ET
import hashlib
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes,padding
import urllib.parse

def flatten_dict(d):
    items = []
    for k, v in d.items():
        if isinstance(v, dict):
            # If the value is a nested dictionary, flatten it without prefixing with parent key
            items.extend(flatten_dict(v).items())
        else:
            items.append((k, v))
    return dict(items)

# Convert the flattened dictionary to URL-encoded string
def json_to_urlencoded(payload):
    # Flatten the payload to handle any nested dictionaries
    flat_payload = flatten_dict(payload)

    # Convert the flattened dictionary into a URL-encoded string
    return urllib.parse.urlencode(flat_payload, quote_via=urllib.parse.quote)

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


def CAMSDecryptionCKYC(encrypted_data):
    varIVBase64 = base64.b64decode("ZDYzYWZjNzYwYzM1ZDY3ZA==")
    varKeyBase64 = base64.b64decode("ZWI3N2EyODJmZTdkYmJhZDc5ZGEwODZiZDdhYTZlYjI=")

    varIVBuffer = varIVBase64
    varKeyBuffer = varKeyBase64

    try:
        # Decrypt data
        cipher = Cipher(algorithms.AES(varKeyBuffer), modes.CBC(varIVBuffer), backend=default_backend())
        decryptor = cipher.decryptor()

        encrypted_data_bytes = base64.b64decode(encrypted_data)
        decrypted_padded_data = decryptor.update(encrypted_data_bytes) + decryptor.finalize()

        # Remove padding
        pad_length = decrypted_padded_data[-1]
        decrypted_data = decrypted_padded_data[:-pad_length].decode('utf-8')
        
        return decrypted_data
    except Exception as error:
        print(error)
        return None

def encrypt_kra_push_payload(str_plain_text,str_key):
    try:
        # Initialize UTF-8 encoding
        password_bytes = str_key.encode('utf-8')

        # Fixed IV (Initialization Vector)
        iv = b"9/\\~V).A,lY&=t2b"

        # Create AES Cipher object with CBC mode
        cipher = Cipher(algorithms.AES(password_bytes), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Apply PKCS7 padding to the plaintext
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(str_plain_text.encode('utf-8')) + padder.finalize()

        # Encrypt the data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Concatenate IV with the encrypted data and encode as base64
        result = base64.b64encode(iv + encrypted_data).decode('utf-8')

        return result

    except Exception as ex:
        raise ex

def decrypt_kra_push_response(str_cipher_text,str_key):
    try:
        # Decode the Base64 encoded string to get the salt and ciphertext
        arr_salt_and_cipher_text = base64.b64decode(str_cipher_text)

        # Extract the IV (first 16 bytes)
        iv = arr_salt_and_cipher_text[:16]

        # Extract the ciphertext (remaining bytes after the IV)
        cipher_text = arr_salt_and_cipher_text[16:]

        # Convert the key to bytes using UTF-8 encoding
        password_bytes = str_key.encode('utf-8')

        # Create the AES Cipher object with the key, IV, and CBC mode
        cipher = Cipher(algorithms.AES(password_bytes), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        decrypted_padded_data = decryptor.update(cipher_text) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        # Convert the decrypted data to a string
        result = decrypted_data.decode('utf-8')

        return result

    except Exception as ex:
        raise ex
