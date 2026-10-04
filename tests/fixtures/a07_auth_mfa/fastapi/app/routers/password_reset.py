import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from ..db import get_db
from ..mail import send_reset_mail
from ..models import ResetToken, User
from ..security import pwd_context

router = APIRouter(prefix="/auth")
logger = logging.getLogger("auth.reset")


class ForgotBody(BaseModel):
    email: EmailStr


class ResetBody(BaseModel):
    token: str
    password: str = Field(min_length=12, max_length=128)


@router.post("/mobile/password/forgot", status_code=202)
def forgot_mobile(body: ForgotBody, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if user is not None:
        # codit-expect: CWE-338 reset token is a time-based uuid1 (predictable)
        token = uuid.uuid1().hex
        db.add(ResetToken(user_id=user.id, token=token))
        db.commit()
        send_reset_mail(user.email, token)
        # codit-expect: CWE-532 password reset token written to the log
        logger.info("reset token for %s: %s", user.email, token)
    return {"ok": True}


@router.post("/mobile/password/reset")
def reset_mobile(body: ResetBody, db: Session = Depends(get_db)):
    # codit-expect: CWE-640 reset token has no expiry and is never invalidated after use
    row = db.query(ResetToken).filter(ResetToken.token == body.token).first()
    if row is None:
        raise HTTPException(status_code=400, detail="Invalid token")
    user = db.get(User, row.user_id)
    user.password_hash = pwd_context.hash(body.password)
    db.commit()
    return {"ok": True}


@router.post("/v2/password/forgot", status_code=202)
def forgot_v2(body: ForgotBody, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if user is not None:
        # codit-safe: CWE-338 token_urlsafe(32) from the secrets module
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)
        db.add(ResetToken(user_id=user.id, token_hash=hashlib.sha256(token.encode()).hexdigest(), expires_at=expires_at))
        db.commit()
        send_reset_mail(user.email, token)
        logger.info("reset token issued user_id=%s", user.id)
    return {"ok": True}


@router.post("/v2/password/reset")
def reset_v2(body: ResetBody, db: Session = Depends(get_db)):
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    # codit-safe: CWE-640 hashed token, must be unused and not expired, consumed on success
    row = db.query(ResetToken).filter(ResetToken.token_hash == token_hash, ResetToken.used_at.is_(None), ResetToken.expires_at > now).first()
    if row is None:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    user = db.get(User, row.user_id)
    user.password_hash = pwd_context.hash(body.password)
    row.used_at = now
    db.commit()
    return {"ok": True}
