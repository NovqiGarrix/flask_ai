import jwt
import os
from . import load_env

load_env.load()

base_64_secret_key = os.environ.get('JWT_PRIVATE_KEY')
secret_key = base_64_secret_key.encode('utf-8')

# Function to sign a JWT token
def sign_token(payload):
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    return token

# Function to verify a JWT token
def verify_token(token):
    try:
        payload = jwt.decode(token, secret_key, algorithms=['HS256'], verify=True)
        return payload
    except jwt.ExpiredSignatureError:
        print("Expired")
        # Handle expired token
        return None
    except jwt.InvalidTokenError:
        print("Invalid")
        # Handle invalid token
        return None
