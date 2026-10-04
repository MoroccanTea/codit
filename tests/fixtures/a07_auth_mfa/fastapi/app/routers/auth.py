import os
from typing import Optional

import pyotp
from fastapi import APIRouter, Depends, HTTPException
from fastapi_limiter.depends import RateLimiter
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import User
from ..security import (
    create_access_token,
    create_mfa_pending_token,
    get_current_user_legacy,
    get_mfa_pending_user,
    pwd_context,
)

router = APIRouter(prefix="/auth")
MASTER_OTP = os.getenv("SUPPORT_MASTER_OTP", "000000")
MAX_OTP_ATTEMPTS = 5


class LoginBody(BaseModel):
    email: EmailStr
    password: str
    otp: Optional[str] = None
    mfa_verified: bool = False


class OtpBody(BaseModel):
    code: str


@router.post("/v1/login")
def login_v1(body: LoginBody, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if user is None:
        # codit-expect: CWE-204 distinct message reveals that the e-mail is not registered
        raise HTTPException(status_code=404, detail="Email not registered")

    # codit-expect: CWE-256 plaintext password column compared directly
    if user.password != body.password:
        raise HTTPException(status_code=401, detail="Incorrect password")

    if user.totp_secret:
        # codit-expect: CWE-807 client-controlled mfa_verified flag skips the TOTP check
        if body.mfa_verified:
            return {"access_token": create_access_token(user.id)}

        # codit-expect: CWE-308 a missing OTP silently skips verification (fail-open)
        if body.otp is None:
            pass
        elif not pyotp.TOTP(user.totp_secret).verify(body.otp):
            raise HTTPException(status_code=401, detail="Invalid code")
    return {"access_token": create_access_token(user.id)}


@router.post("/mobile/login")
def login_mobile(body: LoginBody, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if user is None or not pwd_context.verify(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    if user.totp_secret:
        # codit-expect: CWE-308 full access token returned together with mfa_required
        return {"mfa_required": True, "access_token": create_access_token(user.id)}
    return {"access_token": create_access_token(user.id)}


# codit-expect: CWE-307 OTP verification without attempt counter or rate limiting
@router.post("/mobile/otp/verify")
def mobile_verify(body: OtpBody, user_id: int = Depends(get_current_user_legacy), db: Session = Depends(get_db)):
    user = db.get(User, user_id)

    # codit-expect: CWE-308 static support OTP accepted for every account
    if body.code == MASTER_OTP:
        return {"access_token": create_access_token(user.id)}
    if pyotp.TOTP(user.totp_secret).verify(body.code):
        return {"access_token": create_access_token(user.id)}
    raise HTTPException(status_code=401, detail="Invalid code")


@router.post("/v2/login", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
def login_v2(body: LoginBody, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if user is None or not pwd_context.verify(body.password, user.password_hash):
        # codit-safe: CWE-204 same error for unknown e-mail and wrong password
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    if user.totp_secret:
        # codit-safe: CWE-308 only a scope=mfa_pending 5-minute token before the second factor
        return {"mfa_required": True, "mfa_token": create_mfa_pending_token(user.id)}
    return {"access_token": create_access_token(user.id)}


# codit-safe: CWE-307 rate limited and capped at 5 failed codes per user
@router.post("/v2/otp/verify", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
def verify_v2(body: OtpBody, user_id: int = Depends(get_mfa_pending_user), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user.otp_failed_attempts >= MAX_OTP_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many attempts")
    if not pyotp.TOTP(user.totp_secret).verify(body.code, valid_window=1):
        user.otp_failed_attempts += 1
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid code")
    user.otp_failed_attempts = 0
    db.commit()
    return {"access_token": create_access_token(user.id)}
