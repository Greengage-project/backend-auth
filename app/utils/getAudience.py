import base64
import json

def getAudience(token):
    try:
        payload_token = token.split(".")[1]
        decoded_payload_token = base64.b64decode(payload_token + "===")
        decoded_payload_token = json.loads(decoded_payload_token)
        audience: str = decoded_payload_token["aud"]
        return audience
    except Exception as e:
        raise e
