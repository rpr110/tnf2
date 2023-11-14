"""
POST /login

GET /employees
GET /employee/employee_id
POST /employee
PUT /employee
DELETE /employee

POST /forgot_password
POST /reset_password

GET /logs
GET /log/stats

BILLING

"""
#############
## Imports ##
#############

import time
import uuid
import base64
from typing import Union
import datetime
import pytz

from sqlalchemy import func


from fastapi import APIRouter, Body, Depends, File, UploadFile, Form, Query, status, Request, Path, Header
from fastapi.responses import ORJSONResponse

from app.utils.dependencies import generateJwtToken, decodeJwtTokenDependancy
from app.utils.schema import *
from app import logger, database_client
from app.utils.models import *
from app.utils.utils import *


##########
## APIs ##
##########

# Setup Router
api = APIRouter(default_response_class=ORJSONResponse)


###########
## Login ##
###########

@api.post("/login")
def login(req_body:LoginRequest=Body(...)):
    
    _id = str(uuid.uuid4())

    with database_client.Session() as session:
        employee_data = session.query(
            Employee
        ).filter(
            Employee.email_id == req_body.email_id
        ).first()

        if not employee_data or employee_data.password != req_body.password or not employee_data.is_active:
            _content = BaseResponse(
                meta=BaseMeta(
                    _id=_id,
                    successful=False,
                    message="invalid credentials"
                ),
                data=None,
                error=BaseError(
                    error_message="invalid credentials"
                )
            )

            return ORJSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content=_content.model_dump())
        

        employee_data = employee_data.to_dict()

        banking_info = session.query(
            CompanyBankingInfo
        ).filter(
            CompanyBankingInfo.company_id == employee_data.get("company",{}).get("company_id",{})
        ).order_by(
            CompanyBankingInfo.update_date.desc()
        ).first()

        employee_data["company"]["banking_info"] = banking_info.to_dict() if banking_info else None

    exclude_data_keys = ("company_id","employee_id","role_id","password","role.role_id","company.company_id","company.billing_id","company.billing_information.billing_frequency_id","company.billing_information.billing_id","company.billing_information.currency_id","company.billing_information.currency.currency_id","company.billing_information.billing_frequency.billing_frequency_id","company.banking_info.company_id","company.banking_info.bank_type_id","company.banking_info.bank_type.bank_type_id")
    remove_keys_from_dict(employee_data, exclude_data_keys)
    employee_data = {"employee":employee_data}

    jwt_token = generateJwtToken(
        exp=100000,
        uid=employee_data.get("employee").get("public_id"), # User ID
        cid=employee_data.get("employee").get("company",{}).get("public_id"), # Company ID
        rid=employee_data.get("employee").get("role",{}).get("public_id"), # Role ID
        sid=_id
    )

    _content = TokenResponse(
        meta=TokenMeta(
            _id=_id,
            successful=True,
            message="login successful",
            token=jwt_token
        ),
        data=employee_data,
        error=None
    )

    return ORJSONResponse(status_code=status.HTTP_200_OK, content=_content.model_dump())
    

@api.post("/forgot_password")
def forgot_password(req_body:ForgotPasswordRequest=Body(...)):
    
    # Create request_id
    _id = str(uuid.uuid4())

    # Check if user exists
    with database_client.Session() as session:
        employee_data = session.query(
            Employee
        ).filter(
            Employee.email_id == req_body.email_id
        ).first()

        if not employee_data or not employee_data.is_active:
            _content = BaseResponse(
                meta=BaseMeta(
                    _id=_id,
                    successful=False,
                    message="invalid credentials"
                ),
                data=None,
                error=BaseError(
                    error_message="invalid credentials"
                )
            )

            return ORJSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content=_content.model_dump())
        
        # Create Verification code
        verification_code = create_verification_code(6)

        verification_code_data = session.query(
            VerificationCode
        ).filter(
            VerificationCode.email_id  == req_body.email_id
        ).first()

        if verification_code_data:
            verification_code_data._code = verification_code
        else:
            new_verification_code = VerificationCode(email_id=req_body.email_id, _code=verification_code)
            session.add(new_verification_code)

        session.commit()
        
        # Send EMAIL
        send_mail(req_body.email_id, "Verification Code", f"Your Verification Code: {verification_code}")

    _content = BaseResponse(
        meta=BaseMeta(
            _id=_id,
            successful=True,
            message=f"verification code sent to {req_body.email_id}"
        ),
        data=None,
        error=None
    )

    return ORJSONResponse(status_code=status.HTTP_200_OK, content=_content.model_dump())


@api.post("/reset_password")
def reset_password(req_body:ResetPasswordRequest = Body(...)):
    # Create request_id
    _id = str(uuid.uuid4())

    # Check if user exists
    with database_client.Session() as session:
        verification_code_data = session.query(
            VerificationCode
        ).filter(
            VerificationCode.email_id == req_body.email_id
        ).first()

        # verification_code_is_expired = ( datetime.datetime.now(pytz.utc) - verification_code_data.create_date.astimezone(pytz.utc) > datetime.timedelta(minutes=5) )
        verification_code_is_expired = False
        if not verification_code_data or verification_code_is_expired or verification_code_data._code != req_body.code:
            _content = BaseResponse(
                meta=BaseMeta(
                    _id=_id,
                    successful=False,
                    message="invalid credentials"
                ),
                data=None,
                error=BaseError(
                    error_message="invalid credentials"
                )
            )

            return ORJSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content=_content.model_dump())
        
        # Change password
        employee_data = session.query(
            Employee
        ).filter(
            Employee.email_id  == req_body.email_id
        ).first()

        employee_data.password = req_body.new_password

        session.commit()

    _content = BaseResponse(
        meta=BaseMeta(
            _id=_id,
            successful=True,
            message=f"password updated for {req_body.email_id}"
        ),
        data=None,
        error=None
    )

    return ORJSONResponse(status_code=status.HTTP_200_OK, content=_content.model_dump())

#############
## Profile ##
#############


@api.get("/roles")
def get_roles(
    *,
    x_verbose:bool=Header(False, alias='x-verbose'),

    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    
    _id = str(uuid.uuid4())
    role_id = decoded_token.get("rid")

    with database_client.Session() as session:

        non_verbose_data = (Roles.role_name, Roles.public_id)
        data_to_query = (Roles,) if x_verbose else non_verbose_data
        role_data = session.query(*data_to_query)
        role_data = role_data.all() if role_id == PortalRole.SUPER_ADMIN.value else role_data.filter(Roles.public_id != PortalRole.SUPER_ADMIN.value).all()
        dictify = lambda data,is_verbose : [i.to_dict() for i in data] if is_verbose else [i._asdict() for i in data]
        role_data = dictify(role_data, x_verbose)
        
        _content = BaseResponse(
            meta=BaseMeta(
                _id=_id,
                successful=True,
                message="retrieved roles"
            ),
            data=role_data,
            error=None
        )

    return ORJSONResponse(status_code=status.HTTP_200_OK, content=_content.model_dump())
        

@api.get("/employees")
def get_all_employees(
    *,
    x_verbose:bool=Header(True, alias='x-verbose'),

    company_id:str=Query(...),
    page_no:int= Query(1),
    items_per_page:int= Query(15),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    _id = str(uuid.uuid4())

    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:

        non_verbose_data = (Employee.public_id, Employee.email_id, Employee.employee_name, Employee.phone_number)
        data_to_query = (Employee,) if x_verbose else non_verbose_data

        if role_id == PortalRole.SUPER_ADMIN.value: # SUPER ADMIN
            if company_id == "all":
                employee_data = session.query( *data_to_query )
            else:
                employee_data = session.query(
                    *data_to_query
                ).join(
                    Company,
                    Company.company_id == Employee.company_id
                ).filter(
                    Company.public_id == company_id
                )
        elif role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value: # ADMIN
            if company_id == decoded_token.get("cid"):
                employee_data = session.query(
                    *data_to_query
                ).join(
                    Company,
                    Company.company_id == Employee.company_id
                ).filter(
                    Company.public_id == company_id
                )
            else:
                _content = BaseResponse(
                    meta=BaseMeta(
                        _id=_id,
                        successful=False,
                        message="unauthorized"
                    ),
                    data=None,
                    error=BaseError(
                        error_message="unauthorized"
                    )
                )
                return ORJSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=_content.model_dump())
        

        total_count = employee_data.with_entities(func.count()).scalar()
        # Pagination
        offset = (page_no - 1) * items_per_page
        employee_data = employee_data.order_by(Employee.create_date).offset(offset).limit(items_per_page)

        if employee_data:
            employee_data = employee_data.all()
            dictify = lambda data,is_verbose : [i.to_dict() for i in data] if is_verbose else [i._asdict() for i in data]
            employee_data = dictify(employee_data, x_verbose)

            if x_verbose:
                exclude_data_keys = ("company_id","employee_id","role_id","password","role.role_id","company.company_id","company.billing_id","company.billing_information.billing_frequency_id","company.billing_information.billing_id","company.billing_information.currency_id","company.billing_information.currency.currency_id","company.billing_information.billing_frequency.billing_frequency_id")
                for i in range(len(employee_data)):
                    remove_keys_from_dict(employee_data[i],exclude_data_keys)

    
    _content = PaginationResponse(
        meta=PaginationMeta(
            _id=_id,
            successful=True,
            message=None,
            pagination_data=PaginationData(
                items_per_page=items_per_page,
                page_no=page_no,
                total_count=total_count,
                page_url=request.url._url
            )
        ),
        data=employee_data,
        error=None
    )

    return ORJSONResponse(status_code=status.HTTP_200_OK, content=_content.model_dump())


@api.get("/employee/{employee_id}")
def get_all_employees(
    *,
    x_verbose:bool=Header(True, alias='x-verbose'),

    employee_id:str=Path(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
    _id = str(uuid.uuid4())
    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:

        non_verbose_data = (Employee.public_id, Employee.email_id, Employee.employee_name, Employee.phone_number)
        data_to_query = (Employee,) if x_verbose else non_verbose_data

        if role_id == PortalRole.SUPER_ADMIN.value:
            employee_data = session.query(
                *data_to_query
            ).filter(
                Employee.public_id == employee_id
            )
        elif role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value:
            employee_data = session.query(
                *data_to_query
            ).join(
                Company,
                Company.company_id == Employee.company_id
            ).filter(
                Employee.public_id == employee_id,
                Company.public_id == decoded_token.get("cid")
            )


        employee_data = employee_data.all()

        if employee_data:
            dictify = lambda data,is_verbose : [i.to_dict() for i in data] if is_verbose else [i._asdict() for i in data]
            employee_data = dictify(employee_data, x_verbose)

            if x_verbose:
                exclude_data_keys = ("company_id","employee_id","role_id","password","role.role_id","company.company_id","company.billing_id","company.billing_information.billing_frequency_id","company.billing_information.billing_id","company.billing_information.currency_id","company.billing_information.currency.currency_id","company.billing_information.billing_frequency.billing_frequency_id")
                for i in range(len(employee_data)):
                    remove_keys_from_dict(employee_data[i],exclude_data_keys)

            _successful, _message, _data, _error, _status_code = True, None, employee_data, None, status.HTTP_200_OK
        else:
            _successful, _message, _data, _error, _status_code = False, None, None, BaseError(error_message="user not found"), status.HTTP_404_NOT_FOUND

    
    _content = BaseResponse(
        meta=BaseMeta(
            _id=_id,
            successful=_successful,
            message=_message
        ),
        data=_data,
        error=_error
    )

    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())

@api.post("/employee")
def create_employee(
    *,
    req_body:CreateEmployeeRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
    _id = str(uuid.uuid4())
    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:
        company_data = session.query(Company).filter(Company.public_id==req_body.company_id).first()
        role_data = session.query(Roles).filter(Roles.public_id==req_body.role_id).first()
        if role_id == PortalRole.SUPER_ADMIN.value:
            employee_data = Employee(
                email_id=req_body.email_id,
                password=req_body.password,
                employee_name=req_body.employee_name,
                phone_number=req_body.phone_number,
                employee_profile_pic=req_body.employee_profile_pic,
                company_id=company_data.company_id,
                role_id=role_data.role_id
            )
            session.add(employee_data)
            _successful, _message, _error, _status_code = True, "created employee", None, status.HTTP_200_OK

        elif role_id == PortalRole.ADMIN.value:
            if decoded_token.get("cid") != company_data.company_id:
                _successful, _message, _error, _status_code = False, "unauthorized", BaseError(error_message="unauthorized"), status.HTTP_401_UNAUTHORIZED
            else:
                employee_data = Employee(
                    email_id=req_body.email_id,
                    password=req_body.password,
                    employee_name=req_body.employee_name,
                    phone_number=req_body.phone_number,
                    employee_profile_pic=req_body.employee_profile_pic,
                    company_id=company_data.company_id,
                    role_id=role_data.role_id
                )
                session.add(employee_data)
                _successful, _message, _error, _status_code = True, "created employee", None, status.HTTP_200_OK
            
        elif role_id == PortalRole.EXPLORER.value:
            _successful, _message, _error, _status_code = False, "unauthorized", BaseError(error_message="unauthorized"), status.HTTP_401_UNAUTHORIZED

        
        session.commit()

    _content = BaseResponse(
        meta=BaseMeta(
            _id=_id,
            successful=_successful,
            message=_message
        ),
        data=None,
        error=_error
    )

    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())


@api.put("/employee/{employee_id}")
def modify_employee(
    *,
    employee_id:str=Path(...),
    req_body:ModifyEmployeeDataRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
    _id = str(uuid.uuid4())
    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:

        if role_id == PortalRole.SUPER_ADMIN.value:
            employee_data = session.query(
                Employee
            ).filter(
                Employee.public_id == employee_id
            )

        elif role_id == PortalRole.ADMIN.value:
            employee_data = session.query(
                Employee
            ).join(
                Employee.company_id == Company.company_id
            ).filter(
                Employee.public_id == employee_id,
                Company.public_id == decoded_token.get("cid")
            )
        elif role_id == PortalRole.EXPLORER.value:
            if employee_id != decoded_token.get("uid"):
                _successful, _message, _error, _status_code = False, "unathorized", BaseError(error_message="unathorized"), status.HTTP_401_UNAUTHORIZED
            employee_data = session.query(
                Employee
            ).join(
                Employee.company_id == Company.company_id
            ).filter(
                Employee.public_id == employee_id
            )

        employee_data = employee_data.first()
        if not employee_data:
            _successful, _message, _error, _status_code = False, "user not found", BaseError(error_message="user not found"), status.HTTP_404_NOT_FOUND
        else:
            employee_data.employee_name = req_body.employee_name
            employee_data.phone_number = req_body.phone_number
            employee_data.employee_profile_pic = req_body.employee_profile_pic

            session.commit()
            _successful, _message, _error, _status_code = True, "updated", None, status.HTTP_200_OK


    
    _content = BaseResponse(
        meta=BaseMeta(
            _id=_id,
            successful=_successful,
            message=_message
        ),
        data=None,
        error=_error
    )

    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())

@api.put("/employee/{employee_id}/update_password")
def update_password(
    *,
    employee_id:str=Path(...),
    req_body:ModifyEmployeePasswordRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
    _id = str(uuid.uuid4())
    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:

        if role_id == PortalRole.SUPER_ADMIN.value:
            employee_data = session.query(
                Employee
            ).filter(
                Employee.public_id == employee_id
            )

        elif role_id == PortalRole.ADMIN.value:
            employee_data = session.query(
                Employee
            ).join(
                Employee.company_id == Company.company_id
            ).filter(
                Employee.public_id == employee_id,
                Company.public_id == decoded_token.get("cid")
            )
        elif role_id == PortalRole.EXPLORER.value:
            if employee_id != decoded_token.get("uid"):
                _successful, _message, _error, _status_code = False, "unathorized", BaseError(error_message="unathorized"), status.HTTP_401_UNAUTHORIZED
            
                _content = BaseResponse(
                    meta=BaseMeta(
                        _id=_id,
                        successful=_successful,
                        message=_message
                    ),
                    data=None,
                    error=_error
                )

                return ORJSONResponse(status_code=_status_code, content=_content.model_dump())


            
            employee_data = session.query(
                Employee
            ).join(
                Employee.company_id == Company.company_id
            ).filter(
                Employee.public_id == employee_id
            )

        employee_data = employee_data.first()
        if not employee_data:
            _successful, _message, _error, _status_code = False, "user not found", BaseError(error_message="user not found"), status.HTTP_404_NOT_FOUND
        else:
            if role_id == PortalRole.EXPLORER.value :
                if req_body.old_password == employee_data.password:
                    employee_data.password = req_body.new_password # change pass
                    _successful, _message, _error, _status_code = True, "password updated", None, status.HTTP_200_OK
                else:
                    _successful, _message, _error, _status_code = False, "invalid credentials", BaseError(error_message="invalid credentials"), status.HTTP_401_UNAUTHORIZED
            else:
                employee_data.password = req_body.new_password
                _successful, _message, _error, _status_code = True, "password updated", None, status.HTTP_200_OK


            session.commit()


    
    _content = BaseResponse(
        meta=BaseMeta(
            _id=_id,
            successful=_successful,
            message=_message
        ),
        data=None,
        error=_error
    )

    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())


@api.delete("/employee/{employee_id}")
def delete_employee(
    *,
    employee_id:str=Path(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
    _id = str(uuid.uuid4())
    role_id =  decoded_token.get("rid")

    
    with database_client.Session() as session:

        if role_id == PortalRole.SUPER_ADMIN.value:
            employee_data = session.query(
                Employee
            ).filter(
                Employee.public_id == employee_id
            )

        elif role_id == PortalRole.ADMIN.value:
            employee_data = session.query(
                Employee
            ).join(
                Employee.company_id == Company.company_id
            ).filter(
                Employee.public_id == employee_id,
                Company.public_id == decoded_token.get("cid")
            )
        elif role_id == PortalRole.EXPLORER.value:
            _successful, _message, _error, _status_code = False, "unathorized", BaseError(error_message="unathorized"), status.HTTP_401_UNAUTHORIZED
            _content = BaseResponse(
                meta=BaseMeta(
                    _id=_id,
                    successful=_successful,
                    message=_message
                ),
                data=None,
                error=_error
            )

            return ORJSONResponse(status_code=_status_code, content=_content.model_dump())



        employee_data = employee_data.first()
        if not employee_data:
            _successful, _message, _error, _status_code = False, "user not found", BaseError(error_message="user not found"), status.HTTP_404_NOT_FOUND
        else:
            session.delete(employee_data)
            session.commit()
            _successful, _message, _error, _status_code = True, "deleted", None, status.HTTP_200_OK


    _content = BaseResponse(
        meta=BaseMeta(
            _id=_id,
            successful=_successful,
            message=_message
        ),
        data=None,
        error=_error
    )

    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())



###############
## Dashboard ##
###############

# Logs
# Stats
# Invoice

####################
## Control Center ##
####################

