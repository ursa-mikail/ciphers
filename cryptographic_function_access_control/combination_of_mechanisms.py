# Example usage
# Generate a shared secret key
secret_key = base64.urlsafe_b64encode(hashlib.sha256(b'secret').digest())

# Store used nonces in a set
used_nonces = set()

def generate_nonce(length=16):
    return base64.urlsafe_b64encode(os.urandom(length)).decode('utf-8')

def generate_combined_hmac(key, message, nonce, timestamp):
    data = f"{message}{nonce}{timestamp}"
    return hmac.new(key, data.encode('utf-8'), hashlib.sha256).hexdigest()

def authenticate_combined_access(key, message, token, nonce, timestamp, time_window=60):
    current_time = int(time.time())
    if abs(current_time - timestamp) > time_window or nonce in used_nonces:
        return False
    expected_token = generate_combined_hmac(key, message, nonce, timestamp)
    if hmac.compare_digest(expected_token, token):
        used_nonces.add(nonce)
        return True
    return False

# Example usage
nonce = generate_nonce()
timestamp = int(time.time())
message = 'function_1'
token = generate_combined_hmac(secret_key, message, nonce, timestamp)

# Should be valid
print(authenticate_combined_access(secret_key, message, token, nonce, timestamp))

# Should fail due to nonce reuse
print(authenticate_combined_access(secret_key, message, token, nonce, timestamp))

# Should fail due to timestamp outside of time window
old_timestamp = timestamp - 100
token = generate_combined_hmac(secret_key, message, nonce, old_timestamp)
print(authenticate_combined_access(secret_key, message, token, nonce, old_timestamp))



"""
True
False
False
"""