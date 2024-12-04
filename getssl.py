import requests
import urllib3

# Make the request
response = requests.get('https://kwikid.kyc.priv.getkwikid.com/dev/kyc/api/v1/ekyc/sendLink')

# Access the underlying HTTP connection
tls_version = response.raw._connection.sock.version()

# Print the TLS version
print(f'TLS version: {tls_version}')

