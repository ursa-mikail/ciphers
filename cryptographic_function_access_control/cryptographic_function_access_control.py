import hmac
import hashlib
import base64

# Generate a shared secret key
secret_key = base64.urlsafe_b64encode(hashlib.sha256(b'some_random_secret').digest())

def generate_hmac(key, message):
    return hmac.new(key, message.encode('utf-8'), hashlib.sha256).hexdigest()

def authenticate_access(key, message, token):
    expected_token = generate_hmac(key, message)
    return hmac.compare_digest(expected_token, token)

def protected_function_1():
    print("Access to Function 1 granted.")

def protected_function_2():
    print("Access to Function 2 granted.")

def call_protected_function(function, key, message, token):
    if authenticate_access(key, message, token):
        function()
    else:
        print("Access denied.")

message_1 = 'function_1'
message_2 = 'function_2'

# Generate valid HMAC tokens
token_1 = generate_hmac(secret_key, message_1)
token_2 = generate_hmac(secret_key, message_2)

# Call protected functions with tokens
call_protected_function(protected_function_1, secret_key, message_1, token_1)
call_protected_function(protected_function_2, secret_key, message_2, token_2)

# Attempt to call with invalid token
invalid_token = generate_hmac(secret_key, 'invalid_message')
call_protected_function(protected_function_1, secret_key, message_1, invalid_token)


"""
Access to Function 1 granted.
Access to Function 2 granted.
Access denied.
"""