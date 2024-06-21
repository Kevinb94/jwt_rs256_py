import jwt
from datetime import datetime, timedelta

app_id = "1122334455"

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

print(token)
