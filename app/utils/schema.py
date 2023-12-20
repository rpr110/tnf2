#############
## Imports ##
#############

import datetime
from typing import Optional, Union
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


###########
## Enums ##
###########

class PortalRole(Enum):
    SUPER_ADMIN = "ECE70147-BE8A-43E4-9E19-350B8EC2DB8A"
    ADMIN = "6E5D878B-FC83-4508-988B-1D40D54EB1DA"
    EXPLORER = "BA398889-B22A-4CCB-A27D-7FBBC610FE92"

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

class ModifyEmployeePasswordRequest(BaseModel):
    old_password:Optional[str]
    new_password:str

class CreateEmployeeRequest(BaseModel):
    email_id:str
    password:str
    employee_name:Optional[str]
    phone_number:Optional[str]
    employee_profile_pic:Optional[str]
    company_id:str
    role_id:str

class RegisterClientRequest(BaseModel):
    # Billing Info
    email_id:str
    fc_cpr:Optional[float]
    pl_cpr:Optional[float]
    floor_cost:Optional[float]
    # currency_id:Optional[float]
    billing_start_date:Optional[datetime.datetime]
    billing_end_date:Optional[datetime.datetime]
    billing_frequency_id:Optional[str]
    # is_public:Optional[bool]

    # Company Info
    company_name:str

    # Company Banking Info
    bank_type_id:Optional[str]
    routing_number:Optional[str]
    product_code:Optional[str]
    sort_code:Optional[str]
    payee_beneficiary:Optional[str]
    gateway_client_id:Optional[str]
    institution_code:Optional[str]
    billing_account_number:Optional[str]
    billing_bank_code:Optional[str]
    billing_account_name:Optional[str]

class UpdateCompanyRequest(BaseModel):
    company_name:str
    is_active:bool

class UpdateCompanyBillingRequest(BaseModel):
    email_id:str
    fc_cpr:Optional[float]
    pl_cpr:Optional[float]
    floor_cost:Optional[float]
    # currency_id:Optional[float]
    billing_start_date:Optional[datetime.datetime]
    billing_end_date:Optional[datetime.datetime]
    billing_frequency_id:Optional[str]
    # is_public:Optional[bool]

class UpdateCompanyBankingRequest(BaseModel):
    # Company Banking Info
    bank_type_id:Optional[str]
    routing_number:Optional[str]
    product_code:Optional[str]
    sort_code:Optional[str]
    payee_beneficiary:Optional[str]
    gateway_client_id:Optional[str]
    institution_code:Optional[str]
    billing_account_number:Optional[str]
    billing_bank_code:Optional[str]
    billing_account_name:Optional[str]



#################################
## SQLALCHEMY Model Formatters ##
#################################

class FormatterModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class CurrencyMaster_MF(FormatterModel):
    
    # public_id:str
    currency_id:str = Field(..., alias='public_id')
    currency_name:str
    create_date:datetime.datetime
    update_date:datetime.datetime

class StatusMaster_MF(FormatterModel):

    # public_id:str
    status_id:str = Field(..., alias='public_id')
    status:str
    create_date:datetime.datetime
    update_date:datetime.datetime

class ServiceMaster_MF(FormatterModel):

    # public_id:str
    service_id:str = Field(..., alias='public_id')
    service_name:str
    service_description:Optional[str]
    create_date:datetime.datetime
    update_date:datetime.datetime

class BankTypeMaster_MF(FormatterModel):

    # public_id:str
    bank_type_id:str = Field(..., alias='public_id')
    bank_type:str
    bank_type_description:Optional[None]
    create_date:datetime.datetime
    update_date:datetime.datetime

class BillingFrequencyMaster_MF(FormatterModel):
    
    # public_id:str
    billing_frequency_id:str = Field(..., alias='public_id')
    billing_frequency:str
    billing_frequency_description:Optional[None]
    create_date:datetime.datetime
    update_date:datetime.datetime

class Roles_MF(FormatterModel):
    # public_id:str
    role_id:str = Field(..., alias='public_id')

    role_name:str
    role_description:Optional[None]
    create_date:datetime.datetime
    update_date:datetime.datetime

class VerificationCode_MF(FormatterModel):

    email_id:str
    _code:str
    create_date:datetime.datetime

class BillingInformation_MF(FormatterModel):

    # public_id:str
    billing_id:str = Field(..., alias='public_id')
    billing_info_name:Optional[str]
    email_id1:Optional[str]
    fc_cpr:float
    pl_cpr:float
    floor_cost: Optional[float]
    billing_start_date:datetime.datetime
    billing_end_date:datetime.datetime
    is_public:bool
    create_date:datetime.datetime
    update_date:datetime.datetime

    currency : Optional[CurrencyMaster_MF]
    billing_frequency : Optional[BillingFrequencyMaster_MF]


class CompanyBankingInfo_MF(FormatterModel):

    routing_number:Optional[str]
    product_code:Optional[str]
    sort_code:Optional[str]
    payee_beneficiary:Optional[str]
    create_date:datetime.datetime
    update_date:datetime.datetime
    gateway_client_id:Optional[str]
    institution_code:Optional[str]
    billing_account_number:Optional[str]
    billing_bank_code:Optional[str]
    billing_account_name:Optional[str]

    bank_type:Optional[BankTypeMaster_MF]


class Company_MF(FormatterModel):
    
    # public_id:str
    company_id:str = Field(..., alias='public_id')
    client_id: str
    company_name: str
    is_active:bool
    create_date:datetime.datetime
    update_date:datetime.datetime

    billing_information:Optional[BillingInformation_MF]
    banking_information:Optional[CompanyBankingInfo_MF]


class Employee_MF(FormatterModel):
    # public_id:str
    employee_id:str = Field(..., alias='public_id')

    employee_name:Optional[str]
    email_id:str
    #password:str
    phone_number:Optional[str]
    employee_profile_pic:Optional[bytes]
    is_active:bool
    create_date:datetime.datetime
    update_date:datetime.datetime

    role:Optional[Roles_MF]
    company:Optional[Company_MF]


class NFaceLogs_MF(FormatterModel):

    public_id:str
    session_code:str
    endpoint:str
    user_id:Optional[str]

    status_code:Optional[int]
    ip_address:Optional[str]
    output:Optional[str]
    execution_time:Optional[float]
    create_date:datetime.datetime
    user_image:Optional[bytes]

    company:Optional[Company_MF]
    status:Optional[StatusMaster_MF]
    service:Optional[ServiceMaster_MF]


class Invoice_MF(FormatterModel):
    # public_id:str
    invoice_id:str = Field(..., alias='public_id')

    start_date:datetime.datetime
    end_date:datetime.datetime
    total_non_issue_calls:int
    amount:float
    payment_status:bool
    payment_date:Optional[datetime.datetime]

    create_date:datetime.datetime
    update_date:datetime.datetime

    company:Optional[Company_MF]
