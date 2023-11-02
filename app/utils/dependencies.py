#############
## Imports ##
#############

import datetime
from jose import jwt
from fastapi import Header, Depends
from fastapi.exceptions import HTTPException

from app.utils.models import Employee, Roles
from app import database_client



####################
## Initialization ##
####################

JWT_SECRET_KEY = "9auZtIe)3In7txp!"
JWT_ALGORITHM = "HS256"

###############
## Functions ##
###############

def generateJwtToken(exp:int, **kwargs) -> str:
    to_encode = kwargs.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(seconds=exp)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm = JWT_ALGORITHM)
    return encoded_jwt

def decodeJwtToken(token:str) -> dict:
    payload = jwt.decode(token, JWT_SECRET_KEY, algorithms = [JWT_ALGORITHM])
    return payload

async def decodeJwtTokenDependancy(token:str=Header(...,alias="x-access-token")):
    try:
        decoded_token = decodeJwtToken(token)
        return decoded_token
    except Exception as e:
        _content = {"meta":{"successful":False,"message":"invalid jwt"},"data":None,"error":{"error_message":"invalid jwt"}}
        raise HTTPException(status_code=401,detail=_content)

# async def getRoles():
#     with database_client.Session() as session:
#         roles = session.query(
#             Roles
#         )
#     return roles

    
