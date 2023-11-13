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
    
    with database_client.Session() as session:

        non_verbose_data = (Roles.role_name, Roles.public_id)
        role_data = session.query(Roles) if x_verbose else session.query( *non_verbose_data )
        role_data = [data.to_dict() for data in role_data.all()] if x_verbose else [data._asdict() for data in role_data.all()] 
        
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
    company_id:str=Query(...),
    page_no:int= Query(1),
    items_per_page:int= Query(15),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    _id = str(uuid.uuid4())

    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:

        if role_id == "ECE70147-BE8A-43E4-9E19-350B8EC2DB8A": # SUPER ADMIN
            if company_id == "all":
                employee_data = session.query(Employee)
            else:
                employee_data = session.query(
                    Employee
                ).join(
                    Company,
                    Company.company_id == Employee.company_id
                ).filter(
                    Company.public_id == company_id
                )
        elif role_id == "6E5D878B-FC83-4508-988B-1D40D54EB1DA": # ADMIN
            if company_id == decoded_token.get("cid"):
                employee_data = session.query(
                    Employee
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
            exclude_data_keys = ("company_id","employee_id","role_id","password","role.role_id","company.company_id","company.billing_id","company.billing_information.billing_frequency_id","company.billing_information.billing_id","company.billing_information.currency_id","company.billing_information.currency.currency_id","company.billing_information.billing_frequency.billing_frequency_id")
            employee_data = [ employee.to_dict() for employee in employee_data]
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
    employee_id:str=Path(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
    _id = str(uuid.uuid4())
    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:


        employee_data = session.query(
            Employee
        ).filter(
            Employee.public_id == employee_id
        )


        if employee_data:
            employee_data = employee_data.all()
            exclude_data_keys = ("company_id","employee_id","role_id","password","role.role_id","company.company_id","company.billing_id","company.billing_information.billing_frequency_id","company.billing_information.billing_id","company.billing_information.currency_id","company.billing_information.currency.currency_id","company.billing_information.billing_frequency.billing_frequency_id")
            employee_data = [ employee.to_dict() for employee in employee_data]
            for i in range(len(employee_data)):
                remove_keys_from_dict(employee_data[i],exclude_data_keys)

    
    _content = BaseResponse(
        meta=BaseMeta(
            _id=_id,
            successful=True,
            message=None
        ),
        data=employee_data,
        error=None
    )

    return ORJSONResponse(status_code=status.HTTP_200_OK, content=_content.model_dump())


@api.put("/employee/{employee_id}")
def modify_employee(
    *,
    employee_id:str=Path(...),
    req_body:ModifyEmployeeDataRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
    _id = str(uuid.uuid4())
    role_id =  decoded_token.get("rid")

    # TO-DO Deal with Roles
    with database_client.Session() as session:
        session.query(
            Employee
        ).filter(
            Employee.public_id == employee_id
        ).update(
            {
                Employee.employee_name: req_body.employee_name,
                Employee.phone_number: req_body.phone_number,
                Employee.employee_profile_pic: req_body.employee_profile_pic
            }
        )
        session.commit()
    
    _content = BaseResponse(
        meta=BaseMeta(
            _id=_id,
            successful=True,
            message="updated"
        ),
        data=None,
        error=None
    )

    return ORJSONResponse(status_code=status.HTTP_200_OK, content=_content.model_dump())


@api.delete("/employee/{employee_id}")
def delete_employee(
    *,
    employee_id:str=Path(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
    _id = str(uuid.uuid4())
    role_id =  decoded_token.get("rid")

    # TO-DO Deal with Roles
    with database_client.Session() as session:
        deleted_employee = session.query(
            Employee
        ).filter(
            Employee.public_id == employee_id
        ).first()

        if deleted_employee:
            session.delete(deleted_employee)
            session.commit()
    
    _content = BaseResponse(
        meta=BaseMeta(
            _id=_id,
            successful=True,
            message="deleted"
        ),
        data=None,
        error=None
    )

    return ORJSONResponse(status_code=status.HTTP_200_OK, content=_content.model_dump())



###############
## Dashboard ##
###############

...


####################
## Control Center ##
####################