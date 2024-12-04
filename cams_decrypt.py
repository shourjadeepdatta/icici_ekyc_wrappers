from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

def decrypt_payload(encrypted_payload, key, iv):
    # Convert key and IV from string/base64 to bytes
    key = bytes.fromhex(key)
    iv = base64.b64decode(iv)

    # Decode the encrypted payload from base64
    encrypted_payload_bytes = base64.b64decode(encrypted_payload)

    # Create AES cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt and unpad the payload
    decrypted_payload = unpad(cipher.decrypt(encrypted_payload_bytes), AES.block_size)

    # Convert bytes back to string
    return decrypted_payload.decode('utf-8')

# Your provided parameters
key = "ACB5DEBA6E3D86CA8A30BC7C9187FCBA"  # Corrected to 32 characters
iv = "NmZiYmEzOWFhZjFmZTNhZg=="

# Encrypted payload
encrypted_payload = "LwyUkTJAbs/QSDx0wCxWN5I++kxa/+n+PGkIIvSHFN/8LcdeclZ88T8up4ZSzjIV"

# Decrypt the payload
decrypted = decrypt_payload(encrypted_payload, key, iv)
print("Decrypted payload:", decrypted)


