from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.deps import get_current_user
from app.routers import admin, auth, items, partners

app = FastAPI(title="Inventory API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # codit-expect: CWE-942 wildcard origins combined with allow_credentials=True
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(items.router)
app.include_router(admin.router)
app.include_router(partners.router, dependencies=[Depends(get_current_user)])
