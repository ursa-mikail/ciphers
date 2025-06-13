# Example usage
# Generate a shared secret key
secret_key = base64.urlsafe_b64encode(hashlib.sha256(b'secret').digest())

# Define allowed IP addresses
allowed_ips = ['192.168.1.1', '192.168.1.2']

def generate_hmac_with_ip(key, message, ip_address):
    data = f"{message}{ip_address}"
    return hmac.new(key, data.encode('utf-8'), hashlib.sha256).hexdigest()

def authenticate_access_with_ip(key, message, token, ip_address):
    if ip_address not in allowed_ips:
        return False
    expected_token = generate_hmac_with_ip(key, message, ip_address)
    return hmac.compare_digest(expected_token, token)

# Example usage
ip_address = '192.168.1.1'
message = 'function_1'
token = generate_hmac_with_ip(secret_key, message, ip_address)

# Should be valid for allowed IP
print(authenticate_access_with_ip(secret_key, message, token, ip_address))

# Should fail for non-allowed IP
ip_address = '192.168.1.3'
print(authenticate_access_with_ip(secret_key, message, token, ip_address))


"""
True
False
"""