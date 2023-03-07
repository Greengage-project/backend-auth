from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from app.database import AsyncIOMotorCollection, get_collection
from app import deps, crud
from app.model import UserOutSchema

router = APIRouter()

@router.get("/me", response_model=UserOutSchema)
def me(
    current_user: dict = Depends(deps.get_current_active_user),
) -> Any:
    return current_user

@router.get("/{id}", response_model=UserOutSchema)
async def retrieve(
    id: str,
    current_user: dict = Depends(deps.get_current_user),
    collection: AsyncIOMotorCollection = Depends(get_collection)
) -> Any:
    user = await crud.get(collection, id)
    if not user:
        raise HTTPException(status_code=404, detail=f"User with id '{id}' not found")
    return user

UPDATABLE_KEYS = ["additionalEmails"]

@router.put("/{id}", response_model=UserOutSchema)
async def update(
    id: str,
    payload: dict = Body(...),
    current_user: dict = Depends(deps.get_current_active_user),
    collection: AsyncIOMotorCollection = Depends(get_collection),
) -> Any:
    if not id == current_user.get("sub"):
        raise HTTPException(status_code=403, detail=f"You do not have permission")
    
    keys = payload.keys()
    for key in keys:
        if key not in UPDATABLE_KEYS:
            del payload[key]
            
    await crud.update(collection, id, payload)
    return await crud.get(collection, id)