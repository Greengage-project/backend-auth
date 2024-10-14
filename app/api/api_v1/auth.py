import datetime
from typing import Union

from fastapi import APIRouter, Cookie, Depends, Request
from fastapi.responses import RedirectResponse
from starlette.requests import Request

from app import deps, crud
from app.authentication import oauth
from app.config import settings
from app.database import AsyncIOMotorCollection, get_collection
from urllib.parse import quote_plus, urlencode


router = APIRouter()


@router.get("/login")
async def login(
    request: Request,
    redirect_on_callback: str = f"{settings.COMPLETE_SERVER_NAME}/docs",
    current_user: Union[dict, None] = Depends(deps.get_current_user),
):
    """
    Redirect to Auth0 login page
    """
    if not current_user:
        # redirect_uri = request.url_for('callback')
        redirect_uri = f"{settings.COMPLETE_SERVER_NAME}/callback"
        response = await oauth.keycloak.authorize_redirect(request, redirect_uri)
        request.session["redirect_on_callback"] = redirect_on_callback
        return response
    else:
        print("user already logged in")
        # if user already logged in, redirect to redirect_on_callback
        return RedirectResponse(redirect_on_callback)


@router.get("/callback")
async def callback(request: Request, collection: AsyncIOMotorCollection = Depends(get_collection)):
    """
    Callback from Keycloak login page
    """
    try:
        token = await oauth.keycloak.authorize_access_token(request)
        await crud.update_or_create(collection, token["id_token"], True)
        response = RedirectResponse(request.session.get(
            "redirect_on_callback", "/noredirect"))
        request.session["id_token"] = token["id_token"]
        del request.session["redirect_on_callback"]

        response.set_cookie(
            key="auth_token",
            value=token["id_token"],
            expires=token["expires_in"],
            httponly=True,
            samesite='strict',
            domain=settings.SERVER_NAME,
            secure=settings.PRODUCTION_MODE,
        )

        # user = await oauth.smartcommunitylab.parse_id_token(request, token)
        # print(user)
        return response
    except Exception as err:
        print(err)
        if "mismatching_state" in str(err):
            print("[x] Error in callback: mismatching_state")
            return RedirectResponse(f"{settings.COMPLETE_SERVER_NAME}/auth/login")
        raise err


@router.get("/logout")
async def logout(request: Request, redirect_on_callback: str):
    """
    Redirect to Keycloak logout page
    """

    request.session["redirect_on_callback"] = redirect_on_callback
    url = f"{settings.KEYCLOAK_URL_REALM}/protocol/openid-connect/logout?redirect_uri={redirect_on_callback}/auth/logout_callback&client_id={settings.KEYCLOAK_CLIENT_ID}"
    return RedirectResponse(url)


@router.get("/logout_callback")
async def logout_callback(request: Request):
    """
    Callback from Keycloak logout page
    """
    response = RedirectResponse(request.session.get(
        "redirect_on_callback", "/noredirect"))
    del request.session["redirect_on_callback"]
    del request.session["id_token"]

    # issue of response.delete_cookie(key="auth_token") => https://github.com/tiangolo/fastapi/issues/2268
    expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=1)
    response.set_cookie(
        key="auth_token",
        value="",
        expires=expires.strftime("%a, %d %b %Y %H:%M:%S GMT"),
        httponly=True,
        samesite='strict',
        domain=settings.SERVER_NAME,
        secure=settings.PRODUCTION_MODE,
    )
    return response
