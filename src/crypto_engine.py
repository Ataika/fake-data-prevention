"""
crypto_engine.py
================
Core cryptographic primitives for the Fake Data Prevention system.

Implements:
  - RSA key-pair generation (2048-bit)
  - X.509 self-signed certificate creation (PKI simulation)
  - Message Digest  : SHA-256 hashing
  - Digital Signature: RSA-PSS signing / verification
  - Hybrid Encryption: AES-256-CBC (data) + RSA-OAEP (session key)
  - JWT packaging   : RS256 token creation / verification

Security goals addressed:
  Fabrication  → blocked by Digital Signature (cannot sign without private key)
  Modification → blocked by Message Digest (any change breaks SHA-256 hash)
  Replay       → blocked by JWT exp / jti claims
"""

import hashlib
import json
import base64
import os
import datetime
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import jwt as pyjwt


# ─────────────────────────────────────────────────────────────────────────────
#  1. KEY GENERATION
# ─────────────────────────────────────────────────────────────────────────────

def generate_rsa_keypair(key_size: int = 2048):
    """
    Generate an RSA key-pair.

    Returns:
        (private_key, public_key) — cryptography.hazmat objects
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def save_keypair(private_key, path_prefix: str):
    """Persist PEM-encoded keys to disk (keys/ directory)."""
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"{path_prefix}_private.pem", "wb") as f:
        f.write(priv_pem)
    with open(f"{path_prefix}_public.pem", "wb") as f:
        f.write(pub_pem)
    return priv_pem, pub_pem


# ─────────────────────────────────────────────────────────────────────────────
#  2. X.509 CERTIFICATE  (PKI simulation — in production: issued by a real CA)
# ─────────────────────────────────────────────────────────────────────────────

def create_certificate(private_key, common_name: str, org: str = "UniMe Security Lab"):
    """
    Create a self-signed X.509 certificate binding identity → public key.

    In a real PKI deployment:
      1. Generate CSR (Certificate Signing Request)
      2. Submit to a Certificate Authority (CA)
      3. CA verifies identity, signs the cert → trust chain

    Here we simulate that with a self-signed cert for demonstration.

    Returns:
        x509.Certificate object
    """
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sicily"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Messina"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    return cert


def extract_public_key_from_cert(cert):
    """Extract the signer's public key from a certificate (used by verifier)."""
    return cert.public_key()


def validate_certificate(cert) -> dict:
    """
    Basic certificate validation checks:
      - Not expired
      - Not yet valid
    Returns a dict with validation results.
    """
    now = datetime.datetime.utcnow()
    # Use UTC-aware properties to avoid deprecation warnings
    try:
        not_before = cert.not_valid_before_utc.replace(tzinfo=None)
        not_after  = cert.not_valid_after_utc.replace(tzinfo=None)
    except AttributeError:
        not_before = cert.not_valid_before
        not_after  = cert.not_valid_after

    result = {
        "valid": True,
        "common_name": cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        "not_before": not_before,
        "not_after":  not_after,
        "serial":     cert.serial_number,
        "errors": []
    }
    if now < not_before:
        result["valid"] = False
        result["errors"].append("Certificate not yet valid")
    if now > not_after:
        result["valid"] = False
        result["errors"].append("Certificate has expired")
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  3. MESSAGE DIGEST  (Integrity)
# ─────────────────────────────────────────────────────────────────────────────

def compute_digest(data: dict) -> str:
    """
    Compute SHA-256 digest of a transaction row.

    The data dict is serialised with sorted keys to guarantee determinism —
    same data always produces the same hash regardless of key insertion order.

    Returns:
        hex-encoded SHA-256 digest string
    """
    canonical = json.dumps(data, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
#  4. DIGITAL SIGNATURE  (Authenticity + Non-repudiation)
# ─────────────────────────────────────────────────────────────────────────────

def sign_digest(digest_hex: str, private_key) -> str:
    """
    Sign the SHA-256 digest with the sender's private RSA key.

    Uses RSA-PSS (Probabilistic Signature Scheme) — stronger than PKCS1v15
    because it is randomised and resistant to chosen-message attacks.

    Returns:
        base64-encoded signature string
    """
    signature_bytes = private_key.sign(
        digest_hex.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature_bytes).decode("utf-8")


def verify_signature(digest_hex: str, signature_b64: str, public_key) -> bool:
    """
    Verify that the signature was produced by the holder of the matching
    private key.  Returns True on success, False on any failure.
    """
    try:
        sig_bytes = base64.b64decode(signature_b64)
        public_key.verify(
            sig_bytes,
            digest_hex.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
#  5. JWT  (Secure claim container + Replay protection)
# ─────────────────────────────────────────────────────────────────────────────

def create_jwt(tx_data: dict, digest: str, rsa_signature: str,
               private_key, issuer: str = "BankSecureGateway") -> str:
    """
    Pack transaction + security metadata into a signed JWT (RS256).

    JWT structure:
      Header  : {"alg": "RS256", "typ": "JWT"}
      Payload : {
          iss  : issuer identity,
          iat  : issued-at timestamp,
          exp  : expiry (1 hour),
          jti  : unique token ID — prevents Replay attacks,
          sub  : transaction ID,
          data : original transaction row,
          digest      : SHA-256 hash of data,
          rsa_signature: RSA-PSS signature of the digest
      }
      Signature: RS256 (RSA + SHA-256) of Header.Payload

    Integration with the broader security scheme:
      - The RSA signature inside the payload proves data authenticity
      - The JWT RS256 signature seals the whole container
      - jti + exp prevent reuse of intercepted tokens (Replay attacks)
    """
    now = datetime.datetime.utcnow()
    payload = {
        "iss": issuer,
        "iat": now,
        "exp": now + datetime.timedelta(hours=1),
        "jti": str(uuid.uuid4()),          # Unique token ID → anti-replay
        "sub": tx_data.get("tx_id", "unknown"),
        "role": "transaction_record",       # Custom claim
        "data": tx_data,
        "digest": digest,
        "rsa_signature": rsa_signature,
    }
    token = pyjwt.encode(payload, private_key, algorithm="RS256")
    return token


def verify_jwt(token: str, public_key) -> dict:
    """
    Verify JWT signature and expiry.  Returns decoded payload or raises.
    """
    decoded = pyjwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        options={"verify_exp": True}
    )
    return decoded


# ─────────────────────────────────────────────────────────────────────────────
#  6. HYBRID ENCRYPTION  (Confidentiality)
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_token(jwt_token: str, recipient_public_key) -> dict:
    """
    Hybrid encryption:
      1. Generate a random AES-256 session key
      2. Encrypt the JWT string with AES-256-CBC
      3. Encrypt the session key with RSA-OAEP (recipient's public key)

    Why hybrid?
      - RSA is slow for large data → use AES for the payload
      - AES key is small → safe to encrypt with RSA
      - Only the recipient (with their private key) can recover AES key

    Returns:
        dict with ciphertext, iv, encrypted_session_key (all base64)
    """
    session_key = os.urandom(32)   # AES-256
    iv          = os.urandom(16)   # CBC initialisation vector

    # Pad JWT to AES block size (PKCS7-style)
    token_bytes = jwt_token.encode("utf-8") if isinstance(jwt_token, str) else jwt_token
    pad_len     = 16 - (len(token_bytes) % 16)
    token_padded = token_bytes + bytes([pad_len] * pad_len)

    cipher    = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(token_padded) + encryptor.finalize()

    # Encrypt session key with recipient's RSA public key
    enc_session_key = recipient_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "ciphertext":           base64.b64encode(ciphertext).decode(),
        "iv":                   base64.b64encode(iv).decode(),
        "encrypted_session_key": base64.b64encode(enc_session_key).decode(),
    }


def decrypt_token(enc_bundle: dict, recipient_private_key) -> str:
    """
    Reverse hybrid encryption to recover the original JWT string.
    """
    # Recover AES session key
    enc_sk = base64.b64decode(enc_bundle["encrypted_session_key"])
    session_key = recipient_private_key.decrypt(
        enc_sk,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt ciphertext
    ciphertext = base64.b64decode(enc_bundle["ciphertext"])
    iv         = base64.b64decode(enc_bundle["iv"])

    cipher    = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    token_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    pad_len = token_padded[-1]
    return token_padded[:-pad_len].decode("utf-8")
