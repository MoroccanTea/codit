"""Field-level encryption helpers for the customer vault service."""
import os

import jwt
import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from cryptography.hazmat.primitives.asymmetric import rsa

# codit-expect: CWE-321 symmetric key hard-coded in the module
LEGACY_KEY = b"vault-key-2019!!"



DATA_KEY = bytes.fromhex(os.environ["VAULT_DATA_KEY_HEX"])


def encrypt_legacy(plain: bytes) -> bytes:
    # codit-expect: CWE-327 AES-ECB
    cipher = AES.new(LEGACY_KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(plain, 16))


def encrypt_cbc_static(plain: bytes) -> bytes:
    # codit-expect: CWE-321 constant IV reused for every record
    cipher = AES.new(LEGACY_KEY, AES.MODE_CBC, iv=b"\x00" * 16)
    return cipher.encrypt(pad(plain, 16))


def encrypt(plain: bytes) -> bytes:
    nonce = get_random_bytes(12)
    # codit-safe: CWE-327 AES-GCM with a random nonce and a key loaded from the environment
    cipher = AES.new(DATA_KEY, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plain)
    return nonce + tag + ct


def legacy_signing_key():
    # codit-expect: CWE-326 1024-bit RSA key
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)



def signing_key():
    # codit-safe: CWE-326 3072-bit RSA key
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def issue_partner_token(partner_id: str) -> str:
    # codit-expect: CWE-321 JWT signed with a hard-coded secret
    return jwt.encode({"sub": partner_id}, "changeme-partner-secret", algorithm="HS256")



def issue_partner_token_v2(partner_id: str) -> str:
    # codit-safe: CWE-321 signing secret comes from the environment
    return jwt.encode({"sub": partner_id}, os.environ["PARTNER_JWT_SECRET"], algorithm="HS256")


def fetch_rates_legacy():
    # codit-expect: CWE-295 certificate verification disabled
    return requests.get("https://rates.partner.example/v1/eur", verify=False, timeout=5).json()



def fetch_rates():
    # codit-safe: CWE-295 verification on, pinned to the partner CA bundle
    return requests.get("https://rates.partner.example/v1/eur", verify="/etc/ssl/partner-ca.pem", timeout=5).json()
