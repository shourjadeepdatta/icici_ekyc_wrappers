import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

# Provided data
encrypted_payload = "ahGcCgMtu1raVO1QB4YmfrmWEI5t3sOVanSJq7G/DvHwTuMRkxRlFR94E3oCB5h9QKFyhLb6OGe6Fox6tkZmCNTR1RvIvv4tJCUUHcxKfJCOmzaPFfaHUJf+yg9NnTQftt77DhS9Twa/UCcBJd5VRCVfY4nTNX+SYpO97WNlWHm28bKkaFfZdOgtQzpJ9CrPuwBpnUTUglbJ9JI2Wy7NLtb3UeqgduHbelDDVt4K+byANmBkBRiZuLZHU1xc2fHXCBicf3ehHblSJHeZhhvi+/qvtIRpLvBCBVFcsyyBf6Z9yDlVD1JitHsCU5atOSpGNZ1b4RXeEXxCYKPYRdRMpW/cFj2CGYwic2JFaSF6WSo="
iv = base64.b64decode('NmZiYmEzOWFhZjFmZTNhZg==')
key = base64.b64decode('OGIzOTFhODVhZTc3N2Y4YmFjYTZmZTcyZWRmY2ZjOTE=')

# Base64 decode the encrypted payload
encrypted_bytes = base64.b64decode(encrypted_payload)

# Decrypt the payload
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()
decrypted_padded_bytes = decryptor.update(encrypted_bytes) + decryptor.finalize()

# Remove PKCS7 padding
unpadder = PKCS7(algorithms.AES.block_size).unpadder()
decrypted_bytes = unpadder.update(decrypted_padded_bytes) + unpadder.finalize()

# Convert decrypted bytes to a string
decrypted_string = decrypted_bytes.decode()

print("Decrypted Payload:", decrypted_string)
