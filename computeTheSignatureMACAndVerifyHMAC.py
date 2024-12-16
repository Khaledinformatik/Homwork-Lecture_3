# Lecture 3 :
# Tasks :
# How to compute the signature/MAC code
# and How to verify HMAC: To verify if mac is the valid HMAC code of M with respect to the key K,
#  Just check: mac =? HMAC(K, M)

import hashlib
import hmac
import os
import tweakedTLSHandshakeProtocolUsingSockets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.asymmetric import dsa, ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


HASH_FUNC = hashes.SHA256() # Use SHA256
KEY_LEN = 32 # 32 bytes

# --- Helper Functions ---
def hkdf_extract(salt, input_key_material, length= KEY_LEN):
    """Simplified HKDF Extract."""
    hkdf_extract = HKDF(
        algorithm= HASH_FUNC,
        length=length,  # Length of the PRK (match SHA-256 output: 32 bytes)
        salt=salt,  # Salt can be any value or None
        info=None,  # No info for Extract phase
        backend=default_backend()
    )
    prk = hkdf_extract.derive(input_key_material)
    return prk

def hkdf_expand(prk, info,length = KEY_LEN ):
    # Expand: Derive the final key from the PRK
    hkdf_expand = HKDF(
        algorithm=HASH_FUNC,
        length=length,  # Desired output length of the final derived key
        salt=None,  # No salt in the Expand phase (PRK is used directly as key)
        info=info,  # Context-specific info parameter
        backend=default_backend()
    )
    derived_key = hkdf_expand.derive(prk)
    return derived_key




# ... (Code for generating and managing DSA keys, certificates, etc.)

#  Server Signature Generation

def generate_server_signature(private_key, nonceC, X, nonceS, Y, cert_pks):
    # Creating the message
    message = nonceC + X + nonceS + Y + cert_pks.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Compute the digest of the message
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    message_digest = digest.finalize()

    # Sign the digest using ECDSA with P256 curve
    signature = private_key.sign(
        message_digest,
        ec.ECDSA(Prehashed(hashes.SHA256()))
    )
    return signature

# Helper function to compute HMAC
def compute_hmac(key, message):
       mac = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
       mac.update(message)
       return mac.finalize()

k2s, k2c = tweakedTLSHandshakeProtocolUsingSockets.keyschedule2()

#  Server MAC Generation
def generate_server_mac(k2s, nonceC, X, nonceS, Y, signature, cert_pks):
    # Creating the message
    message = nonceC + X + nonceS + Y + b"ServerMac" +cert_pks.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Compute the digest of the message
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    message_digest = digest.finalize()
    # Compute the mac_server
    mac_server = compute_hmac(k2s, digest)

    return  mac_server


#  Client MAC Generation
def generate_client_mac(k2c, nonceC, X, nonceS, Y, signature, cert_pks):
    # Creating the message
    message = nonceC + X + nonceS + Y + b"ClientMac" +cert_pks.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Compute the digest of the message
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    message_digest = digest.finalize()

    #macs = compute_hmac(K2c,hashlib.sha256(message_macs).digest())
    mac_client = hmac.HMAC(k2c, digest, backend=default_backend())
    mac_client.update(message)
    return  mac_client

#  usage
if __name__ == "__main__":
    # Generate ECDSA private key
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Example nonces and public keys
    nonceC = os.urandom(16)
    X = b"client_public_key"
    nonceS = os.urandom(16)
    Y = b"server_public_key"

    # Example certificate public key
    cert_pks = private_key.public_key()

    # Generate server signature
    signature = generate_server_signature(private_key, nonceC, X, nonceS, Y, cert_pks)
    print(f"Server's signature: {signature.hex()}")


#   2. How to verify HMAC: To verify if mac is the valid HMAC code of M with respect to
#      the key K, Just check: mac =? HMAC(K, M)

# Function to verify HMAC
def verify_hmac(key, message, mac):
    expected_mac = compute_hmac(key, message)
    return hmac.compare_digest(expected_mac, mac)

# verification usage
if __name__ == "__main__":

 # HMAC Verification
  def verify_client_mac(key,message, k2c, nonceC, X, nonceS, Y, cert_pks):

    expected_mac = generate_client_mac(k2c, nonceC, X, nonceS, Y, cert_pks)
    received_mac = compute_hmac(key, message)
    # Use hmac.compare_digest for secure comparison (prevents timing attacks)
    if hmac.compare_digest(received_mac, expected_mac):
        print("Client MAC verification successful")
        return True
    else:
        print("Client MAC verification failed")
        return False

 # HMAC Verification
  def verify_server_mac(key,message, k2s, nonceC, X, nonceS, Y, cert_pks):
    expected_mac = generate_server_mac(k2s, nonceC, X, nonceS, Y, cert_pks)
    received_mac = compute_hmac(key, message)
    # Use hmac.compare_digest for secure comparison
    if hmac.compare_digest(received_mac, expected_mac):
        print("Server MAC verification successful")
        return True
    else:
        print("Server MAC verification failed")
        return False
