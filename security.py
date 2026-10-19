import os
import hmac
import hashlib
from cryptography.fernet import Fernet
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

ph = PasswordHasher()

def _pepper():
    value = os.environ['PASSWORD_PEPPER']
    return bytes.fromhex(value)

def digest(password):
    return hmac.new(_pepper(), password.encode('utf-8'), hashlib.sha256).hexdigest()

def hash_password(password):
    return ph.hash(digest(password))

def verify_password(stored, candidate):
    try:
        return ph.verify(stored, digest(candidate))
    except VerificationError:
        return False

def encrypt_totp(secret):
    return Fernet(os.environ['TOTP_ENCRYPTION_KEY'].encode()).encrypt(secret.encode()).decode()

def decrypt_totp(value):
    return Fernet(os.environ['TOTP_ENCRYPTION_KEY'].encode()).decrypt(value.encode()).decode()
