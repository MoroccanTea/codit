from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.deps import get_db, require_admin
from app.models import User

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])


@router.get("/users")  # codit-safe: CWE-862 router-level dependencies=[Depends(require_admin)]
def list_users(db: Session = Depends(get_db)):
    return db.query(User).order_by(User.email).all()


@router.delete("/users/{user_id}", status_code=204)  # codit-safe: CWE-862,CWE-639 router-level require_admin; admins manage any account
def delete_user(user_id: int, db: Session = Depends(get_db)):
    db.query(User).filter(User.id == user_id).delete()
    db.commit()
