# Example usage
# Generate a shared secret key
secret_key = base64.urlsafe_b64encode(hashlib.sha256(b'secret').digest())

# Define roles and their access rights
roles_permissions = {
    'admin': ['function_1', 'function_2'],
    'user': ['function_1']
}

def generate_hmac_with_role(key, message, role):
    data = f"{message}{role}"
    return hmac.new(key, data.encode('utf-8'), hashlib.sha256).hexdigest()

def authenticate_access_with_role(key, message, token, role):
    if message not in roles_permissions.get(role, []):
        return False
    expected_token = generate_hmac_with_role(key, message, role)
    return hmac.compare_digest(expected_token, token)

# Example usage
role = 'admin'
message = 'function_1'
token = generate_hmac_with_role(secret_key, message, role)

# Should be valid for admin
print(authenticate_access_with_role(secret_key, message, token, role))

# Should fail for user
role = 'user'
print(authenticate_access_with_role(secret_key, message, token, role))

"""
True
False
"""