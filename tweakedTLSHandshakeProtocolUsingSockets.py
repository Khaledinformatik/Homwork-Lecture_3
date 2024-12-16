# Lecture 3 :
# Implement the tweaked TLS handshake protocol (in the Client-Server setting using sockets)
# • Use the simplified key schedule algorithm:
import hmac
import hashlib
import os
import socket
import curve
import ecdh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

HASH_FUNC = hashes.SHA256() # Use SHA256
KEY_LEN = 32 # 32 bytes

# --- Helper Functions ---
def hkdf_extract(salt, input_key_material, length= KEY_LEN  ):
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

def derive_hs(shared_secret_bytes):
    """DeriveHS implementation."""
    es = hkdf_extract(b'\x00' * 32, b'',KEY_LEN )
    des = hkdf_expand(es, hashlib.sha256("DerivedES".encode()).digest(), KEY_LEN)
    hs = hkdf_extract(des, hashlib.sha256(shared_secret_bytes).digest(),KEY_LEN)
    return hs

def keyschedule1(shared_secret_bytes):
    """KeySchedule1 implementation."""
    hs = derive_hs(shared_secret_bytes)
    k1c = hkdf_expand(hs, hashlib.sha256("ClientKE".encode()).digest(), KEY_LEN)
    k1s = hkdf_expand(hs, hashlib.sha256("ServerKE".encode()).digest(), KEY_LEN)
    return k1c, k1s


def keyschedule2(nonce_c, X, nonce_s, Y , shared_secret_bytes):
    """KeySchedule2 implementation."""
    hs = derive_hs(shared_secret_bytes)
    client_kc_input = nonce_c +X + nonce_s + Y + b"ClientKC"
    server_kc_input = nonce_c + X + nonce_s + Y + b"ServerKC"
    client_kc = hashlib.sha256(client_kc_input).digest()
    server_kc = hashlib.sha256(server_kc_input).digest()
    k2c = hkdf_expand(hs, client_kc)
    k2s = hkdf_expand(hs, server_kc)
    return k2c, k2s


def keyschedule3(nonce_c, X, nonce_s,Y, shared_secret_bytes, signature, certificate_bytes, macs):
    """KeySchedule3 implementation."""
    hs = derive_hs(shared_secret_bytes)
    dhs = hkdf_expand(hs, hashlib.sha256("DerivedHS".encode()).digest(), KEY_LEN)
    ms = hkdf_extract(dhs, bytes(32))
    client_skh_input = nonce_c + X + nonce_s + Y + signature + certificate_bytes + macs + b"ClientEncK"
    server_skh_input = nonce_c + X + nonce_s + Y + signature + certificate_bytes + macs + b"ServerEncK"
    client_skh = hashlib.sha256(client_skh_input).digest()
    server_skh = hashlib.sha256(server_skh_input).digest()
    k3c = hkdf_expand(ms, client_skh)
    k3s = hkdf_expand(ms, server_skh)
    return k3c, k3s

# --- TLS Handshake Implementation ---

class TlsParticipant:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.nonce = os.urandom(16)

    def generate_diffie_hellman_public(self):
        return self.public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)

    def compute_shared_secret(self, peer_public_key_bytes):
        peer_public_key = ec.EllipticCurvePublicKey.from_pem(peer_public_key_bytes, default_backend())
        return self.private_key.exchange(ecdh.ECDH(), peer_public_key)

class TlsClient(TlsParticipant):
    def __init__(self):
        super().__init__()
        self.server_public_key_bytes = None
        self.shared_secret_bytes = None
        self.k1c = None
        self.k1s = None
        self.k2c = None
        self.k2s = None
        self.k3c = None
        self.k3s = None
        self.server_nonce = None

    def initiate_handshake(self, server_socket):
        # 1. Send Client Hello
        client_public_key_bytes = self.generate_diffie_hellman_public()
        server_socket.send(client_public_key_bytes)
        print("Client: Sent Client Hello (Public Key)")

        # 2. Receive Server Hello (Server's public key)
        self.server_public_key_bytes = server_socket.recv(1024)
        print("Client: Received Server Hello (Server Public Key)")

        # Compute shared secret and KeySchedule1
        self.shared_secret_bytes = self.compute_shared_secret(self.server_public_key_bytes)
        self.k1c, self.k1s = keyschedule1(self.shared_secret_bytes)
        print("Client: Computed Shared Secret and KeySchedule1")

        # 3. Send Client Nonce and Public Key, Receive Server Nonce and Public Key
        message = self.nonce + self.generate_diffie_hellman_public()
        server_socket.send(message)
        print("Client: Sent Client Nonce and Public Key")

        server_response = server_socket.recv(1024)
        self.server_nonce = server_response[:16]
        server_public_key_bytes_ks2 = server_response[16:]
        print("Client: Received Server Nonce and Public Key")

        # KeySchedule2
        self.k2c, self.k2s = keyschedule2(self.nonce, self.generate_diffie_hellman_public(), self.server_nonce, server_public_key_bytes_ks2, self.shared_secret_bytes)
        print("Client: Computed KeySchedule2")


        # --- Placeholder for Certificate, Signature, MACs ---
        # In a real TLS, this is where certificates, signatures, and MACs are exchanged and verified.
        # For simplicity, we'll use placeholder values here.
        signature = b"clientsignature"
        certificate_bytes = b"clientcertificate"
        macs = b"clientmacs"

        # 4. Send (Placeholder) Signature, Certificate, MACs
        client_ks3_data = signature + certificate_bytes + macs
        server_socket.send(client_ks3_data)
        print("Client: Sent (Placeholder) Signature, Certificate, MACs")

        # Receive (Placeholder) Server Signature, Certificate, MACs
        server_ks3_data = server_socket.recv(1024)
        server_signature = server_ks3_data[:15]
        server_certificate_bytes = server_ks3_data[15:130]
        server_macs = server_ks3_data[130:]
        print("Client: Received (Placeholder) Server Signature, Certificate, MACs")

        # KeySchedule3
        self.k3c, self.k3s = keyschedule3(self.nonce, self.generate_diffie_hellman_public(), self.server_nonce, self.server_public_key_bytes, self.shared_secret_bytes, signature, certificate_bytes, macs)
        print("Client: Computed KeySchedule3")
        print("Client: Handshake complete. Session keys established.")

class TlsServer(TlsParticipant):
    def __init__(self):
        super().__init__()
        self.client_public_key_bytes = None
        self.shared_secret_bytes = None
        self.k1c = None
        self.k1s = None
        self.k2c = None
        self.k2s = None
        self.k3c = None
        self.k3s = None
        self.client_nonce = None

    def handle_connection(self, client_socket):
        # 1. Receive Client Hello (Client's public key)
        self.client_public_key_bytes = client_socket.recv(1024)
        print("Server: Received Client Hello (Client Public Key)")

        # 2. Send Server Hello (Server's public key)
        server_public_key_bytes = self.generate_diffie_hellman_public()
        client_socket.send(server_public_key_bytes)
        print("Server: Sent Server Hello (Server Public Key)")

        # Compute shared secret and KeySchedule1
        self.shared_secret_bytes = self.compute_shared_secret(self.client_public_key_bytes)
        self.k1c, self.k1s = keyschedule1(self.shared_secret_bytes)
        print("Server: Computed Shared Secret and KeySchedule1")

        # 3. Receive Client Nonce and Public Key, Send Server Nonce and Public Key
        client_message = client_socket.recv(1024)
        self.client_nonce = client_message[:16]
        client_public_key_bytes_ks2 = client_message[16:]
        print("Server: Received Client Nonce and Public Key")

        response_message = self.nonce + self.generate_diffie_hellman_public()
        client_socket.send(response_message)
        print("Server: Sent Server Nonce and Public Key")

        # KeySchedule2
        self.k2c, self.k2s = keyschedule2(self.client_nonce, client_public_key_bytes_ks2, self.nonce, self.generate_diffie_hellman_public(), self.shared_secret_bytes)
        print("Server: Computed KeySchedule2")

        # --- Placeholder for Certificate, Signature, MACs ---
        signature = b"serversignature"
        certificate_bytes = b"servercertificate"
        macs = b"servermacs"

        # 4. Receive (Placeholder) Signature, Certificate, MACs
        client_ks3_data = client_socket.recv(1024)
        client_signature = client_ks3_data[:15]
        client_certificate_bytes = client_ks3_data[15:130]
        client_macs = client_ks3_data[130:]
        print("Server: Received (Placeholder) Client Signature, Certificate, MACs")

        # Send (Placeholder) Signature, Certificate, MACs
        server_ks3_data = signature + certificate_bytes + macs
        client_socket.send(server_ks3_data)
        print("Server: Sent (Placeholder) Signature, Certificate, MACs")

        # KeySchedule3
        self.k3c, self.k3s = keyschedule3(self.client_nonce, self.client_public_key_bytes, self.nonce, self.generate_diffie_hellman_public(), self.shared_secret_bytes, signature, certificate_bytes, macs)
        print("Server: Computed KeySchedule3")
        print("Server: Handshake complete. Session keys established.")

# --- Main Execution ---
if __name__ == "__main__":
    host = '127.0.0.1'
    port = 12345

    # Start Server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print("Server: Listening for connections...")
    server_conn, server_addr = server_socket.accept()
    print(f"Server: Connected by {server_addr}")
    tls_server = TlsServer()
    tls_server.handle_connection(server_conn)

    # Start Client
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"Client: Connected to {host}:{port}")
    tls_client = TlsClient()
    tls_client.initiate_handshake(client_socket)

    # Optionally, we  can print the derived keys for verification
    print("\n--- Session Keys ---")
    print(f"Client K1C: {tls_client.k1c.hex() if tls_client.k1c else None}")
    print(f"Client K1S: {tls_client.k1s.hex() if tls_client.k1s else None}")
    print(f"Client K2C: {tls_client.k2c.hex() if tls_client.k2c else None}")
    print(f"Client K2S: {tls_client.k2s.hex() if tls_client.k2s else None}")
    print(f"Client K3C: {tls_client.k3c.hex() if tls_client.k3c else None}")
    print(f"Client K3S: {tls_client.k3s.hex() if tls_client.k3s else None}")

    print(f"Server K1C: {tls_server.k1c.hex() if tls_server.k1c else None}")
    print(f"Server K1S: {tls_server.k1s.hex() if tls_server.k1s else None}")
    print(f"Server K2C: {tls_server.k2c.hex() if tls_server.k2c else None}")
    print(f"Server K2S: {tls_server.k2s.hex() if tls_server.k2s else None}")
    print(f"Server K3C: {tls_server.k3c.hex() if tls_server.k3c else None}")
    print(f"Server K3S: {tls_server.k3s.hex() if tls_server.k3s else None}")

    # Close connections
    server_conn.close()
    server_socket.close()
    client_socket.close()