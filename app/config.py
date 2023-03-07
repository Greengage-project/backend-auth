from typing import List

from pydantic import AnyHttpUrl
import secrets
from typing import Any, Dict, List, Optional, Union

from pydantic import AnyHttpUrl, BaseSettings, EmailStr, HttpUrl, PostgresDsn, validator
import os

class Settings(BaseSettings):
    SECRET_KEY: str = secrets.token_urlsafe(32)
    # BACKEND_CORS_ORIGINS is a JSON-formatted list of origins
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []

    MONGODB_URL: str
    MONGODB_DATABASE: str
    COLLECTION_NAME: str
    
    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    CLIENT_ID: str
    CLIENT_SECRET: str
    SERVER_URL: str
    SERVER_METADATA_URL: str

    AUTH0_CLIENT_ID: str
    AUTH0_CLIENT_SECRET: str
    AUTH0_DOMAIN: str
    

    PROTOCOL: str
    SERVER_NAME: str
    BASE_PATH: str
    COMPLETE_SERVER_NAME: AnyHttpUrl = os.getenv("PROTOCOL") + os.getenv("SERVER_NAME") + os.getenv("BASE_PATH")
    API_V1_STR: str = "/api/v1"
    
    PRODUCTION_MODE : bool =  "https" in os.getenv("PROTOCOL")
    PROJECT_NAME : str = "Auth API"

settings = Settings()
