# Lecture 3 :
# Task :
# How to deal with the certificate

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed



# Generate server key pair (𝑝𝑘𝑆, 𝑆𝑘𝑆)
server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
server_public_key = server_private_key.public_key()

# Hardcode the server key pair into the server program
SERVER_PRIVATE_KEY_PEM = server_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

SERVER_PUBLIC_KEY_PEM = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Generate CA key pair (𝑝𝑘CA, 𝑆𝑘CA)
ca_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
ca_public_key = ca_private_key.public_key()

# Hardcode the CA public key into the server and client programs
CA_PUBLIC_KEY_PEM = ca_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save the CA private key for signing purposes
CA_PRIVATE_KEY_PEM = ca_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Server and Client programs
CA_PUBLIC_KEY_PEM = b"""
-----BEGIN PUBLIC KEY-----
... (public key content) ...
-----END PUBLIC KEY-----
"""


# Load CA private key
ca_private_key = serialization.load_pem_private_key(CA_PRIVATE_KEY_PEM, password=None, backend=default_backend())

# Sign the server's public key
signature = ca_private_key.sign(
    SERVER_PUBLIC_KEY_PEM,
    ec.ECDSA(hashes.SHA256())
)

# Save signature
SERVER_SIGNATURE = signature

# Hardcode server certificate
cert = {
    "server_public_key": SERVER_PUBLIC_KEY_PEM,
    "signature": SERVER_SIGNATURE
}

# Load CA public key
ca_public_key = serialization.load_pem_public_key(CA_PUBLIC_KEY_PEM, backend=default_backend())

# Assume cert is received from the server
cert = {
    "server_public_key": b"... (server public key) ...",
    "signature": b"... (signature) ..."
}

# Verify the certificate
server_public_key = serialization.load_pem_public_key(cert["server_public_key"], backend=default_backend())
signature = cert["signature"]

try:
    ca_public_key.verify(
        signature,
        cert["server_public_key"],
        ec.ECDSA(hashes.SHA256())
    )
    print("Certificate verification succeeded.")
except:
    print("Certificate verification failed.")
