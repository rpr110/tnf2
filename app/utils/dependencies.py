#############
## Imports ##
#############

import datetime
from jose import jwt
from fastapi import Header, status, Request
from fastapi.exceptions import HTTPException

from app import redis_client, logger
from app.utils.models import Employee, Roles
from app.utils.schema import BaseResponse, BaseMeta, BaseError



####################
## Initialization ##
####################

JWT_SECRET_KEY = "9auZtIe)3In7txp!"
JWT_ALGORITHM = "HS256"

###############
## Functions ##
###############

def generate_jwt_token(exp:int, **kwargs) -> str:
    to_encode = kwargs.copy()
    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=exp)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm = JWT_ALGORITHM)
    return encoded_jwt

def decode_jwt_token(token:str) -> dict:
    payload = jwt.decode(token, JWT_SECRET_KEY, algorithms = [JWT_ALGORITHM])
    return payload

async def decode_jwt_token_dependancy(*, token:str=Header(...,alias="x-access-token"), request:Request):
    try:
        # create request id
        _id = request.state.session_code
        logger.info(f"[{_id}] validating jwt")

        token_email = redis_client.get_data(token)
        if not token_email:
            raise ValueError("token doesnt exist")

        decoded_token = decode_jwt_token(token)
        return decoded_token
    except Exception as e:
        logger.info(f"[{_id}] invalid jwt {e}")
        _content = BaseResponse(
            meta=BaseMeta(
                _id="",
                successful=False,
                message="invalid jwt"

            ),
            data=None,
            error=BaseError(
                error_message="invalid jwt"
            )
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail=_content.model_dump())

