import jwt
from datetime import datetime, timedelta
import requests

app_id = "1122334455"
installation_id = "your_installation_id"  # Replace with your installation ID

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
