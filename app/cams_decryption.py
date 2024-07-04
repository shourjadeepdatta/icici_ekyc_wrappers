import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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

# Example encrypted data (replace this with your actual encrypted data)
encrypted_data = "POBnWw/bNTo8wtDmUYrpDjR6lz3Jsx1xY/ZD+s4s+uo4uOzJFvUq9IXUAsS7krOjdyeIfHbvWDTG6C4ZwJoe3AmvJ+askBw8og62ypTjknI175OFMlmIr4Q3QNyokGU8zn8VBpjQp4o2Gj2EfE6LnZOkpHUUTII3JBQJj0F6mblTI6eRs+2xKhcaKzkWUuAg/fd2yxGW6FZir2yHRtZgepZgh/t2qIK2Ll9jcR8IlWyB77V2lfJo9nU77X0sSxs+"
decrypted_data = CAMSDecryptionCKYC(encrypted_data)
print(decrypted_data)
