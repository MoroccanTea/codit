from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.deps import get_db
from app.security import issue_token, verify_password
from app.models import User

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/token")  # codit-safe: CWE-862 OAuth2 password-grant token endpoint is public by design
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username).first()
    if user is None or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    return {"access_token": issue_token(user, form.scopes), "token_type": "bearer"}
