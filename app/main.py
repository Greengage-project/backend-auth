from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from starlette.middleware.cors import CORSMiddleware
from app.api.api_v1.auth import router as authrouter
from app.api.api_v1.users import router as usersrouter
from app.config import settings
from app.database import connect_to_mongo, close_mongo_connection

# BASE PATH can be "" or "/auth"
# not using root_path because oidc returns redirect_uri mismatch openapi_prefix=settings.BASE_PATH, 
app = FastAPI(
    title=settings.PROJECT_NAME, openapi_url=f"{settings.BASE_PATH}/openapi.json", docs_url=f"{settings.BASE_PATH}/docs"
)
app.add_event_handler("startup", connect_to_mongo)
app.add_event_handler("shutdown", close_mongo_connection)

# Set all CORS enabled origins
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        # allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

@app.get(f"{settings.BASE_PATH}/")
def main():
    return RedirectResponse(url=f"{settings.BASE_PATH}/docs")

@app.get(f"{settings.BASE_PATH}/healthcheck")
def healthcheck():
    return True

app.include_router(authrouter, prefix=settings.BASE_PATH, tags=["auth"])
app.include_router(usersrouter, prefix=f"{settings.BASE_PATH}{settings.API_V1_STR}/users", tags=["users"])

###################
# we need this to save temporary code & state in session (authentication)
###################

#from app.general.authentication import AuthMiddleware
#app.add_middleware(AuthMiddleware)


from starlette.middleware.sessions import SessionMiddleware
app.add_middleware(
    SessionMiddleware, 
    secret_key=settings.SECRET_KEY, 
    same_site="none",
    https_only=True,
    session_cookie="session",
    domain=".greengage-project.eu"
)

###################
# Staticfiles
###################

from fastapi.staticfiles import StaticFiles
app.mount(f"{settings.BASE_PATH}/static", StaticFiles(directory="static"), name="static")