# Cryptographic Function Access Control

Provides a secure access control system for cryptographic functions using HMAC (Hash-based Message Authentication Code). It supports multiple mechanisms to enhance security, including time-based access control, nonce-based access control, role-based access control, and IP address-based access control.

## Features
- **Secret-Based Access Control**: Ensures that the token is only valid for a specific secrets.
- **Time-Based Access Control**: Ensures that the HMAC token is only valid for a specific time window.
- **Nonce-Based Access Control**: Prevents replay attacks by using a unique nonce for each function call.
- **Role-Based Access Control (RBAC)**: Controls access based on the user's role, allowing only authorized roles to access specific functions.
- **IP Address-Based Access Control**: Restricts access based on the requestor's IP address.
- **Combination of Mechanisms**: Provides stronger security by combining multiple access control mechanisms.

