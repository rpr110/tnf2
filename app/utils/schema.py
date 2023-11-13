#############
## Imports ##
#############

from typing import Optional, Union
from enum import Enum

from pydantic import BaseModel


###########
## Enums ##
###########


######################
## Response Schemas ##
######################

class BaseMeta(BaseModel):
    _id:str
    successful:bool
    message:Optional[str]

class BaseError(BaseModel):
    error_message:str

class BaseResponse(BaseModel):
    meta:BaseMeta
    data:Union[dict,list,None]
    error:Optional[BaseError]


class TokenMeta(BaseMeta):
    token:Optional[str]
class TokenResponse(BaseResponse):
    meta:TokenMeta


class LoginRequest(BaseModel):
    email_id:str
    password:str

class ForgotPasswordRequest(BaseModel):
    email_id:str

class ResetPasswordRequest(BaseModel):
    email_id:str
    code:str
    new_password:str

class PaginationData(BaseModel):
    items_per_page:Optional[int]
    page_no:Optional[int]
    total_count:Optional[int]
    page_url:Optional[str]

class PaginationMeta(BaseMeta):
    pagination_data:PaginationData

class PaginationResponse(BaseResponse):
    meta:PaginationMeta


class ModifyEmployeeDataRequest(BaseModel):
    employee_name:Optional[str]
    phone_number:Optional[str]
    employee_profile_pic:Optional[str]
