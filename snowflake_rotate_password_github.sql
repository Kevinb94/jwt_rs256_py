CREATE OR REPLACE PROCEDURE rotate_password_and_update_github(
    user_name STRING, 
    app_id STRING, 
    secret_name STRING, 
    installation_id STRING, 
    organization STRING, 
    github_secret_name STRING
)
RETURNS STRING
LANGUAGE PYTHON
RUNTIME_VERSION = '3.8'
PACKAGES = ('snowflake-snowpark-python', 'requests', 'cryptography', 'pyjwt')
HANDLER = 'rotate_password_and_update_github'
EXTERNAL_ACCESS_INTEGRATIONS = ('GitHub_api_access_integration')
SECRETS = ('private_key_secret' = secret_name)
AS
$$
import _snowflake
import snowflake.snowpark
import jwt
import requests
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
import secrets

def rotate_password_and_update_github(session, user_name, app_id, secret_name, installation_id, organization, github_secret_name):
    try:
        # Fetch the private key from Snowflake secret storage
        private_key = _snowflake.get_generic_secret_string('private_key_secret')

        # Step 1: Generate the JWT for GitHub authentication
        now = datetime.utcnow()
        expiry = now + timedelta(minutes=10)
        payload = {
            "iat": int(now.timestamp()),  # Convert to int
            "exp": int(expiry.timestamp()),  # Convert to int
            "iss": app_id
        }
        token = jwt.encode(payload, private_key, algorithm="RS256")

        # Step 2: Get the installation access token from GitHub
        url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json"
        }
        response = requests.post(url, headers=headers)
        if response.status_code == 201:
            access_token = response.json()["token"]
        else:
            raise Exception(f"Failed to create installation access token: {response.status_code} {response.json()}")

        # Step 3: Get the public key for the GitHub organization
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
        else:
            raise Exception(f"Failed to get public key: {response.status_code} {response.json()}")

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

        # Generate a new secure password
        new_password = secrets.token_urlsafe(16)

        # Encrypt the new password using the GitHub public key
        encrypted_secret = encrypt_secret(key, new_password)

        # Step 4: Update the GitHub organization secret
        url = f"https://api.github.com/orgs/{organization}/actions/secrets/{github_secret_name}"
        payload = {
            "encrypted_value": encrypted_secret,
            "key_id": key_id
        }
        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github+json"
        }

        response = requests.put(url, headers=headers, json=payload)
        if response.status_code != 201 and response.status_code != 204:
            raise Exception(f"Failed to update secret: {response.status_code} {response.json()}")

        # Step 5: Rotate the password in Snowflake
        session.sql(f"""
            ALTER USER {user_name}
            SET PASSWORD = '{new_password}'
        """).collect()

        return "Password rotated and secret updated successfully"
    except Exception as e:
        return f"Error: {str(e)}"

$$;
