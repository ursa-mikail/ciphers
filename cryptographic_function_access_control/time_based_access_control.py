import hmac
import hashlib
import base64
import time

# Generate a shared secret key
secret_key = base64.urlsafe_b64encode(hashlib.sha256(b'secret').digest())

def generate_hmac(key, message, timestamp):
    data = f"{message}{timestamp}"
    return hmac.new(key, data.encode('utf-8'), hashlib.sha256).hexdigest()

def authenticate_access(key, message, token, timestamp, time_window=10):  # default 10 secs
    current_time = int(time.time())
    if abs(current_time - timestamp) > time_window:
        return False
    expected_token = generate_hmac(key, message, timestamp)
    return hmac.compare_digest(expected_token, token)

# Example usage
timestamp = int(time.time())
message = 'function_1'
token = generate_hmac(secret_key, message, timestamp)
print(f"Timestamp: {timestamp}")
print(f"Token: {token}")

timestamp_earlier = timestamp - 100
token_01 = generate_hmac(secret_key, message, timestamp)

# Should be within the time window
print(authenticate_access(secret_key, message, token, timestamp))
print(authenticate_access(secret_key, message, token, timestamp_earlier))
print(authenticate_access(secret_key, message, token_01, timestamp_earlier))

default_time = 11 # expiring the time for all tokens
time.sleep(default_time) 
print(authenticate_access(secret_key, message, token, timestamp))
print(authenticate_access(secret_key, message, token_01, timestamp_earlier))

"""
Timestamp: 1734679751
Token: e18ce7ac8264f2487442655e4e0bdb79a8393dca7707ad7d74af14a6a296f3ab
True
False
False

False
False
"""