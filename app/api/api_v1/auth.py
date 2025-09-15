import datetime
from typing import Union, Iterable 

from fastapi import APIRouter, Cookie, Depends, Request
from fastapi.responses import RedirectResponse
from starlette.requests import Request

from app import deps, crud
from app.authentication import oauth
from app.config import settings
from app.database import AsyncIOMotorCollection, get_collection
from urllib.parse import quote_plus, urlencode


router = APIRouter()


def _domain_variants(hostname: str) -> Iterable[str]:
    """
    Generate possible domain variants for setting cookies.
    E.g. for "sub.example.com" yield:
    - "sub.example.com"
    - ".example.com"
    """
    yield hostname
    root = settings.SERVER_NAME  
    if root:
        yield root if root.startswith(".") else f".{root}"

def wipe_session_and_cookies(request: Request, response: RedirectResponse) -> None:
    """
    Wipe out session and cookies by setting them to expire in the past.

    Args:
    - request: FastAPI Request object
    - response: FastAPI Response object where cookies will be set to expire
    """

    # 1) limpia la sesión
    try:
        request.session.clear()
    except Exception as e:
        print(f"[wipe] error clearing session: {e}")

    expires = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).strftime("%a, %d %b %Y %H:%M:%S GMT")

    hostname = request.url.hostname or ""
    paths = {"/", settings.BASE_PATH or "/"}
    for ck in list(request.cookies.keys()):
        for dom in _domain_variants(hostname):
            for p in paths:
                try:
                    response.set_cookie(
                        key=ck,
                        value="",
                        expires=expires,
                        max_age=0,
                        path=p,
                        domain=dom,
                        secure=True,
                        httponly=True,
                        samesite="none",
                    )
                except Exception as e:
                    print(f"[wipe] error deleting cookie {ck} for {dom}{p}: {e}")

@router.get("/login")
async def login(
    request: Request,
    redirect_on_callback: str = f"{settings.COMPLETE_SERVER_NAME}/docs",
    current_user: Union[dict, None] = Depends(deps.get_current_user),
):
    """
    Redirect to Auth0 login page
    """
    print("[login] session keys before redirect:", request.session.keys())
    print("[login] setting redirect_on_callback:", redirect_on_callback)
    if not current_user:
        # redirect_uri = request.url_for('callback')
        redirect_uri = f"{settings.COMPLETE_SERVER_NAME}/callback"
        response = await oauth.keycloak.authorize_redirect(request, redirect_uri, prompt="select_account")
        request.session["redirect_on_callback"] = redirect_on_callback
        return response
    else:
        print("user already logged in")
        # if user already logged in, redirect to redirect_on_callback
        return RedirectResponse(redirect_on_callback)


@router.get("/callback", name="callback")
async def callback(request: Request, collection: AsyncIOMotorCollection = Depends(get_collection)):
    """
    Callback from Keycloak login page
    """
    print("[callback] session keys on return:", request.session.keys())
    print("[callback] received state:", request.query_params.get("state"))
    try:
        token = await oauth.keycloak.authorize_access_token(request)

        id_token = token["id_token"]
        expires_in = int(token.get("expires_in", 3600))

        await crud.update_or_create(collection, id_token, True)

        request.session["id_token"] = id_token

        redirect_to = request.session.pop("redirect_on_callback", "/")
        resp = RedirectResponse(redirect_to)

        resp.set_cookie(
            key="auth_token",
            value=id_token,
            max_age=expires_in,
            httponly=True,
            samesite="none",
            secure=True,
            domain=(settings.SERVER_NAME if settings.SERVER_NAME else request.url.hostname),
            path="/",
        )
        return resp

    except Exception as err:
        print("[callback] error:", err)
        reason = str(err)

        attempt = int(request.query_params.get("attempt", "0") or 0)

        if "mismatching_state" in reason:
            login_url = str(request.url_for("login"))

            if attempt >= 1:
                return PlainTextResponse(
                    "Login failed (CSRF state mismatch) after retry. Please reload and try again.",
                    status_code=400,
                )

            redirect_on_callback = request.session.get("redirect_on_callback", "/dashboard")
            retry_url = f"{login_url}?redirect_on_callback={redirect_on_callback}&attempt=1"

            resp = RedirectResponse(retry_url, status_code=302)
            wipe_session_and_cookies(request, resp)
            for k in ("auth_token", "next-auth.session-token", "__Secure-next-auth.session-token"):
                resp.set_cookie(key=k, value="", max_age=0, expires=0, path="/",
                                domain=(settings.SERVER_NAME if settings.SERVER_NAME else request.url.hostname),
                                secure=True, httponly=True, samesite="none")
            return resp

        return PlainTextResponse(f"Login failed: {reason}", status_code=400)



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
    try:
        del request.session["id_token"]
    except KeyError:
        print("No id_token found in session, skipping deletion.")
    # issue of response.delete_cookie(key="auth_token") => https://github.com/tiangolo/fastapi/issues/2268
    expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=1)
    response.set_cookie(
        key="auth_token",
        value="",
        expires=expires.strftime("%a, %d %b %Y %H:%M:%S GMT"),
        httponly=True,
        samesite='none',
        domain=settings.SERVER_NAME,
        secure=settings.PRODUCTION_MODE,
    )
    try:
        request.session.clear()
    except Exception as e:
        print(f"Error clearing session: {e}")
    return response
