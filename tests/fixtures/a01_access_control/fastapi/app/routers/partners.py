from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.deps import get_db
from app.models import Partner

# Authentication is applied where the router is mounted:
#   app.include_router(partners.router, dependencies=[Depends(get_current_user)])
router = APIRouter(prefix="/partners", tags=["partners"])


@router.get("/")  # codit-safe: CWE-862 include_router(..., dependencies=[Depends(get_current_user)]) in main.py
def list_partners(db: Session = Depends(get_db)):
    return db.query(Partner).filter(Partner.public.is_(True)).all()


@router.get("/{slug}")  # codit-safe: CWE-862 include-level get_current_user dependency
def partner_detail(slug: str, db: Session = Depends(get_db)):
    return db.query(Partner).filter(Partner.slug == slug, Partner.public.is_(True)).first()
