import hashlib
import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext

SECRET_KEY = os.environ["JWT_SECRET"]
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/v2/login")

# codit-safe: CWE-916 bcrypt with 12 rounds for all new hashes
pwd_context = CryptContext(schemes=["bcrypt"], bcrypt__rounds=12, deprecated="auto")

# accounts imported from the old PHP shop
# codit-expect: CWE-916 bcrypt with only 4 rounds
legacy_context = CryptContext(schemes=["bcrypt"], bcrypt__rounds=4)


def hash_password_legacy(password: str, salt: bytes) -> bytes:
    # codit-expect: CWE-916 PBKDF2 with 1,000 iterations
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000)


def hash_password_pbkdf2(password: str, salt: bytes) -> bytes:
    # codit-safe: CWE-916 PBKDF2-SHA256 with 600,000 iterations (OWASP 2023 guidance)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


def create_access_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    # codit-safe: CWE-613 15-minute access token
    payload = {"sub": str(user_id), "scope": "access", "iat": now, "exp": now + timedelta(minutes=15)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_mfa_pending_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user_id), "scope": "mfa_pending", "iat": now, "exp": now + timedelta(minutes=5)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_legacy_token(user_id: int) -> str:
    # codit-expect: CWE-613 JWT without an exp claim never expires
    return jwt.encode({"sub": str(user_id), "scope": "access"}, SECRET_KEY, algorithm=ALGORITHM)


def create_remember_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    # codit-expect: CWE-613 365-day bearer token
    payload = {"sub": str(user_id), "scope": "access", "iat": now, "exp": now + timedelta(days=365)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user_legacy(token: str = Depends(oauth2_scheme)) -> int:
    """Dependency of the /mobile routes."""
    try:
        # codit-expect: CWE-308 any valid JWT is accepted, including scope=mfa_pending tokens
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return int(payload["sub"])


async def get_current_user(token: str = Depends(oauth2_scheme)) -> int:
    """Dependency of the /v2 routes."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    # codit-safe: CWE-308 mfa_pending tokens are rejected, only scope=access counts as a full login
    if payload.get("scope") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Second factor required")
    return int(payload["sub"])


async def get_mfa_pending_user(token: str = Depends(oauth2_scheme)) -> int:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    if payload.get("scope") != "mfa_pending":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return int(payload["sub"])
