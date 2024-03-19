#############
## Imports ##
#############

import datetime
from typing import Optional, Union, List, Any
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
    email_id:Optional[str]
    password:Optional[str]
    msauth_token:Optional[str] = None

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
    is_active:bool = 1

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
    floor_cost:Optional[float]
    vat:Optional[float]

    billing_start_date:Optional[datetime.datetime]
    billing_end_date:Optional[datetime.datetime]
    billing_frequency_id:Optional[str]
    billing_mode_type_id:Optional[str]
    institution_id:Optional[str]
    volume_tariff:Optional[List]

    # Company Info
    company_name:str
    client_id:Optional[str]
    auto_disable_days:Optional[int]

    # Company Banking Info
    bank_type_id:Optional[str]
    routing_number:Optional[str]
    product_code:Optional[str]
    sort_code:Optional[str]
    payee_beneficiary:Optional[str]
    institution_code:Optional[str]
    billing_account_number:Optional[str]
    billing_bank_code:Optional[str]
    billing_account_name:Optional[str]

class UpdateCompanyRequest(BaseModel):
    company_name:str
    client_id:str
    is_active:bool
    auto_disable_days:Optional[int]

class UpdateCompanyBillingRequest(BaseModel):
    email_id1:str
    floor_cost:Optional[float]
    vat:Optional[float]
    billing_start_date:Optional[datetime.datetime]
    billing_end_date:Optional[datetime.datetime]
    billing_frequency_id:Optional[str]
    billing_mode_type_id:Optional[str]
    institution_id:Optional[str]
    volume_tariff:Optional[List]

class UpdateCompanyBankingRequest(BaseModel):
    # Company Banking Info
    bank_type_id:Optional[str]
    routing_number:Optional[str]
    product_code:Optional[str]
    sort_code:Optional[str]
    payee_beneficiary:Optional[str]
    institution_code:Optional[str]
    billing_account_number:Optional[str]
    billing_bank_code:Optional[str]
    billing_account_name:Optional[str]

class CreateInstitutionRequest(BaseModel):
    institution_name:str
    floor_cost:Optional[float]
    vat:Optional[float]
    billing_start_date:Optional[datetime.datetime]
    billing_end_date:Optional[datetime.datetime]
    billing_frequency_id:Optional[str]
    billing_mode_type_id:Optional[str]
    volume_tariff:Optional[List]

class UpdateInstitutionRequest(CreateInstitutionRequest):
    ...
class AddVolumeTariffRequest(BaseModel):
    item_id:str
    min_vol:int
    max_vol:int
    rate:float


#################################
## SQLALCHEMY Model Formatters ##
#################################

class FormatterModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)



class CurrencyMasterMF(FormatterModel):
    
    currency_id:str = Field(..., alias='public_id')
    currency_name:str
    create_date:datetime.datetime
    update_date:datetime.datetime

class StatusMasterMF(FormatterModel):

    status_id:str = Field(..., alias='public_id')
    status:str
    create_date:datetime.datetime
    update_date:datetime.datetime

class ServiceMasterMF(FormatterModel):

    service_id:str = Field(..., alias='public_id')
    service_name:str
    service_description:Optional[str]
    create_date:datetime.datetime
    update_date:datetime.datetime

class BankTypeMasterMF(FormatterModel):

    
    bank_type_id:str = Field(..., alias='public_id')
    bank_type:str
    bank_type_description:Optional[None]
    create_date:datetime.datetime
    update_date:datetime.datetime

class BillingFrequencyMasterMF(FormatterModel):
    
    
    billing_frequency_id:str = Field(..., alias='public_id')
    billing_frequency:str
    billing_frequency_description:Optional[None]
    create_date:datetime.datetime
    update_date:datetime.datetime

class BillingModeTypeMasterMF(FormatterModel):
    
    
    billing_mode_type_id:Union[str,Any] = Field(..., alias='public_id')
    billing_mode_type:str
    billing_mode_type_description:Optional[None]
    create_date:datetime.datetime
    update_date:Optional[datetime.datetime]

class RolesMF(FormatterModel):
    
    role_id:str = Field(..., alias='public_id')

    role_name:str
    role_description:Optional[None]
    create_date:datetime.datetime
    update_date:datetime.datetime

class VerificationCodeMF(FormatterModel):

    email_id:str
    _code:str
    create_date:datetime.datetime


class WalletMF(FormatterModel):
    wallet_id:Union[str,Any] = Field(..., alias='public_id')
    amount:float
    ledger_amount:float
    create_date:datetime.datetime
    update_date:Optional[datetime.datetime]

class VolumeTariffMF(FormatterModel):
    tariff_id:Union[str,Any] = Field(..., alias='public_id')
    min_volume:int
    max_volume:int
    rate:float
    create_date:datetime.datetime
    update_date:Optional[datetime.datetime]


class InstitutionMF(FormatterModel):
    institution_id:Union[str,Any] = Field(..., alias='public_id')
    institution_name:str
    floor_cost: Optional[float]
    vat:float
    billing_start_date:datetime.datetime
    billing_end_date:datetime.datetime

    currency : Optional[CurrencyMasterMF]
    billing_mode_type: Optional[BillingModeTypeMasterMF]
    billing_frequency : Optional[BillingFrequencyMasterMF]
    volume_tariff: Union[List[VolumeTariffMF],  None ]
    create_date:datetime.datetime
    update_date:Optional[datetime.datetime]


class BillingInformationMF(FormatterModel):

    
    billing_id:str = Field(..., alias='public_id')
    email_id1:Optional[str]
    floor_cost: Optional[float]
    billing_start_date:datetime.datetime
    billing_end_date:datetime.datetime
    create_date:datetime.datetime
    update_date:datetime.datetime
    vat:float

    billing_mode_type: Optional[BillingModeTypeMasterMF]
    currency : Optional[CurrencyMasterMF]
    billing_frequency : Optional[BillingFrequencyMasterMF]
    institution: Optional[InstitutionMF]
    volume_tariff: Union[List[VolumeTariffMF], None]



class CompanyBankingInfoMF(FormatterModel):

    routing_number:Optional[str]
    product_code:Optional[str]
    sort_code:Optional[str]
    payee_beneficiary:Optional[str]
    create_date:datetime.datetime
    update_date:datetime.datetime
    institution_code:Optional[str]
    billing_account_number:Optional[str]
    billing_bank_code:Optional[str]
    billing_account_name:Optional[str]

    bank_type:Optional[BankTypeMasterMF]


class CompanyMF(FormatterModel):
    
    
    company_id:Union[str, Any] = Field(..., alias='public_id')
    client_id: str
    company_name: str
    is_active:bool
    create_date:datetime.datetime
    update_date:datetime.datetime

    billing_information:Optional[BillingInformationMF]
    banking_information:Optional[CompanyBankingInfoMF]
    wallet:Optional[WalletMF]


class EmployeeMF(FormatterModel):
    
    employee_id:str = Field(..., alias='public_id')

    employee_name:Optional[str]
    email_id:str
    phone_number:Optional[str]
    employee_profile_pic:Optional[bytes]
    is_active:bool
    create_date:datetime.datetime
    update_date:datetime.datetime

    role:Optional[RolesMF]
    company:Optional[CompanyMF]


class NFaceLogsMF(FormatterModel):

    public_id:str
    session_code:str
    endpoint:str
    user_id:Optional[str]

    status_code:Optional[int]
    ip_address:Optional[str]
    output:Optional[str]
    execution_time:Optional[float]
    create_date:datetime.datetime
    user_image:Optional[str]

    company:Optional[CompanyMF]
    status:Optional[StatusMasterMF]
    service:Optional[ServiceMasterMF]


class InvoiceMF(FormatterModel):
    
    invoice_id:str = Field(..., alias='public_id')

    start_date:datetime.datetime
    end_date:datetime.datetime
    total_requests:Optional[int]
    total_non_issue_requests:Optional[int]
    total_issue_requests:Optional[int]
    total_success_requests:Optional[int]
    total_failure_requests:Optional[int]
    amount:float
    payment_status:bool
    payment_date:Optional[datetime.datetime]

    create_date:datetime.datetime
    update_date:datetime.datetime

    company:Optional[CompanyMF]

