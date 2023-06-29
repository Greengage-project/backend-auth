import jwt
from app.config import settings
from authlib.integrations.starlette_client import OAuth
from jwt import PyJWKClient



url = settings.KEYCLOAK_URL_REALM
url_openid = f"{url}/.well-known/openid-configuration"

oauth = OAuth()


oauth.register(
    name="keycloak",
    client_id=settings.KEYCLOAK_CLIENT_ID,
    client_secret=settings.KEYCLOAK_CLIENT_SECRET,
    server_metadata_url=f"{url}/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid profile",
    },
)


def decode_token(jwtoken):
    jwks_client = PyJWKClient(url + "/protocol/openid-connect/certs")
    signing_key = jwks_client.get_signing_key_from_jwt(jwtoken)
    data = jwt.decode(
        jwtoken,
        signing_key.key,
        algorithms=["RS256"],
        audience=settings.KEYCLOAK_CLIENT_ID,
        # options={"verify_nbf": False},
    )
    return data
