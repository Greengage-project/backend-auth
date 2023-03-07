from typing import Generator

from app.utils.getAudience import getAudience

from fastapi import Depends, HTTPException, Request
from app import crud
from app.database import AsyncIOMotorCollection, get_collection

def get_token_in_cookie(request):
    try:
        return request.cookies.get("auth_token")
    except:
        return None

def get_audience_in_cookie(request):
    try:
        return request.cookies.get("audience")
    except:
        return None

def get_token_in_header(request):
    try:
        return request.headers.get('authorization').replace("Bearer ", "")
    except:
        return None

def get_current_token(
    request: Request
) -> dict:
    return get_token_in_cookie(request) or get_token_in_header(request)

async def get_current_user(
    request: Request,
   collection: AsyncIOMotorCollection = Depends(get_collection)
) -> dict:
    try:
        
        token = get_token_in_cookie(request) or get_token_in_header(request)
        audience = get_audience_in_cookie(request)
        if token:
            if not audience:
                audience = getAudience(token)
            return await crud.update_or_create(collection, token, False, audience)
        return None
    except Exception as e:
        raise e

def get_current_active_user(
    current_user: dict = Depends(get_current_user),
) -> dict:
    # calls get_current_user, and if nothing is returned, raises Not authenticated exception
    if not current_user:
        raise HTTPException(status_code=403, detail="Not authenticated")
    return current_user


def get_current_active_superuser(
    current_user: dict = Depends(get_current_user),
) -> dict:
    if True:
        raise HTTPException(
            status_code=403, detail="The user doesn't have enough privileges"
        )
    return current_user
