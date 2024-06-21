import jwt
from datetime import datetime, timedelta
import requests
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64

app_id = "1122334455"
installation_id = "your_installation_id"  # Replace with your installation ID
organization = "your_organization_name"   # Replace with your organization name
secret_name = "YOUR_SECRET_NAME"           # Replace with your secret name
secret_value = "your_secret_value"         # Replace with your secret value

# Read the contents of the private key file
with open("private.pem", "r") as f:
    private_key = f.read()

# Set the current time and expiry time (10 minutes from now)
now = datetime.utcnow()
expiry = now + timedelta(minutes=10)

# Prepare the payload
payload = {
    "iat": int(now.timestamp()),  # Convert to int
    "exp": int(expiry.timestamp()),  # Convert to int
    "iss": app_id
}

# Generate the JWT
token = jwt.encode(payload, private_key, algorithm="RS256")

# GitHub API URL for creating an installation access token
url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"

# HTTP headers
headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json"
}

# Make the request to get the installation access token
response = requests.post(url, headers=headers)

# Check the response
if response.status_code == 201:
    print("Installation access token successfully created!")
    access_token = response.json()["token"]
    print(f"Access Token: {access_token}")
else:
    print(f"Failed to create installation access token: {response.status_code}")
    print(response.json())

print(token)


# Get the public key for the organization
url = f"https://api.github.com/orgs/{organization}/actions/secrets/public-key"
headers = {
    "Authorization": f"token {access_token}",
    "Accept": "application/vnd.github+json"
}

response = requests.get(url, headers=headers)
if response.status_code == 200:
    public_key = response.json()
    key_id = public_key["key_id"]
    key = public_key["key"]
    print("Public key retrieved successfully")
else:
    print(f"Failed to get public key: {response.status_code}")
    print(response.json())
    exit()


# Encrypt the secret
def encrypt_secret(public_key: str, secret_value: str) -> str:
    public_key_bytes = base64.b64decode(public_key)
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )
    encrypted = public_key.encrypt(
        secret_value.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

encrypted_secret = encrypt_secret(key, secret_value)
print("Secret encrypted successfully")

# Update the organization secret
url = f"https://api.github.com/orgs/{organization}/actions/secrets/{secret_name}"
payload = {
    "encrypted_value": encrypted_secret,
    "key_id": key_id
}
headers = {
    "Authorization": f"token {access_token}",
    "Accept": "application/vnd.github+json"
}

response = requests.put(url, headers=headers, json=payload)
if response.status_code == 201 or response.status_code == 204:
    print("Secret updated successfully")
else:
    print(f"Failed to update secret: {response.status_code}")
    print(response.json())