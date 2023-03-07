import jwt
from app.config import settings
from authlib.integrations.starlette_client import OAuth
from jwt import PyJWKClient

url = "https://dev-btw6zvhat22wdzmr.us.auth0.com"

oauth = OAuth()

oauth.register(
    "auth0",
    client_id=settings.AUTH0_CLIENT_ID,
    client_secret=settings.AUTH0_CLIENT_SECRET,
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{settings.AUTH0_DOMAIN}/.well-known/openid-configuration'
)

def decode_token(jwtoken, audience=None):
    jwks_client = PyJWKClient(url + "/.well-known/jwks.json")
    signing_key = jwks_client.get_signing_key_from_jwt(jwtoken)
    data = jwt.decode(
        jwtoken,
        signing_key.key,
        algorithms=["RS256"],
        audience=audience,
        # options={"verify_nbf": False},
    )
    return data