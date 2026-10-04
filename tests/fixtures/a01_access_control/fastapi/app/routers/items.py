from decimal import Decimal
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Security
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.deps import get_current_user, get_db
from app.models import Item, User

router = APIRouter(prefix="/items", tags=["items"])


class ItemCreate(BaseModel):
    name: str
    quantity: int = 0


class PriceOverride(BaseModel):
    price: Decimal


@router.get("/")  # codit-safe: CWE-862 Depends(get_current_user)
def list_items(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Item).filter(Item.owner_id == user.id).all()


@router.post("/", status_code=201)  # codit-safe: CWE-862 Security(get_current_user, scopes=["items:write"])
def create_item(payload: ItemCreate, user: User = Security(get_current_user, scopes=["items:write"]), db: Session = Depends(get_db)):
    item = Item(name=payload.name, quantity=payload.quantity, owner_id=user.id)
    db.add(item)
    db.commit()
    return item


@router.get("/{item_id}")
def read_item(item_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.get(Item, item_id)  # codit-expect: CWE-639 item loaded by path id; owner never compared with user.id
    if item is None:
        raise HTTPException(status_code=404)
    return item


@router.get("/{item_id}/history")
def item_history(item_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.query(Item).filter(Item.id == item_id, Item.owner_id == user.id).first()  # codit-safe: CWE-639 owner-scoped query
    if item is None:
        raise HTTPException(status_code=404)
    return item.history


@router.delete("/{item_id}", status_code=204)  # codit-expect: CWE-862 no auth dependency, unlike every sibling route of this router
def delete_item(item_id: int, db: Session = Depends(get_db)):
    db.query(Item).filter(Item.id == item_id).delete()
    db.commit()


@router.put("/{item_id}/archive")
def archive_item(item_id: int, user: User = Security(get_current_user, scopes=["items:read"]), db: Session = Depends(get_db)):  # codit-expect: CWE-863 state-changing route guarded by the read scope items:read
    item = db.query(Item).filter(Item.id == item_id, Item.owner_id == user.id).first()
    if item is None:
        raise HTTPException(status_code=404)
    item.archived = True
    db.commit()
    return item


@router.post("/{item_id}/price")
def override_price(
    item_id: int,
    payload: PriceOverride,
    x_role: Optional[str] = Header(default=None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if x_role != "manager":  # codit-expect: CWE-807 authorization decided by the client-supplied X-Role header
        raise HTTPException(status_code=403)
    item = db.query(Item).filter(Item.id == item_id, Item.owner_id == user.id).first()
    if item is None:
        raise HTTPException(status_code=404)
    item.price = payload.price
    db.commit()
    return item
