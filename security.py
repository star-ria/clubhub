"""TOTP two-factor authentication helpers (RFC 6238, SHA-1, 6 digits, 30 s steps) + secret encryption.
Standard library only, apart from `cryptography` (Fernet) used to encrypt TOTP secrets at rest."""
import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from urllib.parse import quote

from cryptography.fernet import Fernet

PERIOD, DIGITS, ISSUER = 30, 6, "FST Club Hub"


def _fernet():
    # Set TOTP_ENC_KEY (any long random string) in production; falls back to SECRET_KEY for development.
    seed = os.environ.get("TOTP_ENC_KEY") or os.environ.get("SECRET_KEY", "dev-only-change-me")
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(seed.encode()).digest()))


def encrypt(plain):
    return _fernet().encrypt(plain.encode()).decode()


def decrypt(token):
    return _fernet().decrypt(token.encode()).decode()


def generate_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode()  # 160-bit secret, 32 base32 chars


def hotp(secret_b32, counter, digits=DIGITS):
    key = base64.b32decode(secret_b32, casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(value).zfill(digits)


def totp(secret_b32, at=None, period=PERIOD, digits=DIGITS):
    at = time.time() if at is None else at
    return hotp(secret_b32, int(at // period), digits)


def verify_totp(secret_b32, code, last_step=0, at=None, window=1, period=PERIOD):
    """Returns the accepted time step, or None. Allows +/-1 step of clock drift and refuses any
    step <= last_step, so a code can never be used twice (replay protection)."""
    if not (isinstance(code, str) and len(code) == DIGITS and code.isdigit()):
        return None
    current = int((time.time() if at is None else at) // period)
    accepted = None
    for step in range(current - window, current + window + 1):
        if step > last_step and hmac.compare_digest(hotp(secret_b32, step), code):
            accepted = step
    return accepted


def provisioning_uri(secret_b32, account):
    return f"otpauth://totp/{quote(ISSUER)}:{quote(account)}?secret={secret_b32}&issuer={quote(ISSUER)}&digits={DIGITS}&period={PERIOD}"


def generate_backup_codes(n=8):
    codes = []
    for _ in range(n):
        h = secrets.token_hex(5)
        codes.append(f"{h[:5]}-{h[5:]}")
    return codes


def hash_backup_code(code):
    return hashlib.sha256(code.strip().lower().replace("-", "").replace(" ", "").encode()).hexdigest()
