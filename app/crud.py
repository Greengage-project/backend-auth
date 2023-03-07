from datetime import datetime
import mimetypes
import requests
from fastapi.encoders import jsonable_encoder

from app.database import AsyncIOMotorCollection
from app.model import UserSchema
from app.config import settings
from app.authentication import decode_token


async def get(collection: AsyncIOMotorCollection, id: str):
    return await collection.find_one({
        '$or': [
            {'_id': id},
            {'email': id},
            {'sub': id}
        ]})


async def get_all(collection: AsyncIOMotorCollection):
    return await collection.find().to_list(1000)


def download_profile_image(url, name_save):
    response = requests.get(url)
    content_type = response.headers['content-type']
    extension = mimetypes.guess_extension(content_type)
    URL = f"/static/{name_save}{extension}"
    with open("/app" + URL, 'wb') as handler:
        handler.write(response.content)
    return URL


async def create(collection: AsyncIOMotorCollection, user_info: dict):
    print("CREATING FROM ", user_info)
    user_id = user_info["sub"]
    user_info["_id"] = user_id
    if "picture" in user_info:
        user_info["picture"] = download_profile_image(user_info["picture"], user_id)
    if "given_name" in user_info and "family_name" in user_info:
        user_info["full_name"] = user_info["given_name"] + \
            " " + user_info["family_name"]
    user = UserSchema(**user_info)
    user = jsonable_encoder(user)
    user["_id"] = user_id
    db_asset = await collection.insert_one(user)
    return await get(collection=collection, id=db_asset.inserted_id)


async def update(collection: AsyncIOMotorCollection, id: str, user_info: dict):
    print("UPDATING WITH", user_info)
    user = jsonable_encoder(user_info)
    db_asset = await collection.update_one({"_id": id}, {'$set': user})
    return await get(collection=collection, id=id)


async def delete(collection: AsyncIOMotorCollection, id: str):
    return await collection.delete_one({"_id": id})


async def update_or_create(collection: AsyncIOMotorCollection, token, update_last_login, audience=None):
    user_info: dict = decode_token(token, audience=audience)
    user_id = user_info["sub"]
    db_user_info = await get(collection, user_id)
    if not db_user_info:
        print("Creating user from update_or_create")
        db_user_info = await create(collection=collection, user_info=user_info)
    else:
        if update_last_login:
            db_user_info = await update(collection=collection, id=user_id, user_info={
                "last_login": datetime.now()
            })
    db_user_info["id"] = db_user_info["_id"]
    del db_user_info["_id"]
    print("Returning db user from update_or_create", db_user_info)
    return {**user_info, **db_user_info}
