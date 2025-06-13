import os

# Store used nonces in a set
used_nonces = set()

def generate_nonce(length=16):
    return base64.urlsafe_b64encode(os.urandom(length)).decode('utf-8')

def generate_hmac_with_nonce(key, message, nonce):
    data = f"{message}{nonce}"
    return hmac.new(key, data.encode('utf-8'), hashlib.sha256).hexdigest()

def authenticate_access_with_nonce(key, message, token, nonce):
    if nonce in used_nonces:
        return False
    expected_token = generate_hmac_with_nonce(key, message, nonce)
    if hmac.compare_digest(expected_token, token):
        used_nonces.add(nonce)
        return True
    return False

# Example usage
# Generate a shared secret key
secret_key = base64.urlsafe_b64encode(hashlib.sha256(b'secret').digest())

nonce = generate_nonce()
message = 'function_1'
token = generate_hmac_with_nonce(secret_key, message, nonce)

# Should be a valid nonce
print(authenticate_access_with_nonce(secret_key, message, token, nonce))

# Should fail as nonce is reused
print(authenticate_access_with_nonce(secret_key, message, token, nonce))

"""
True
False
"""