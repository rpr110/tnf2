#############
## Imports ##
#############

import io
import uuid
import csv
import pytz    
import datetime

import pandas as pd

import sqlalchemy
from sqlalchemy import func
from sqlalchemy.orm import selectinload, joinedload, aliased

import requests

from fastapi import APIRouter, Body, Depends, File, UploadFile, Form, Query, status, Request, Path, Header
from fastapi.responses import ORJSONResponse, StreamingResponse

from app.utils.dependencies import generateJwtToken, decodeJwtTokenDependancy
from app.utils.schema import *
from app import database_client, email_client, otp_client, redis_client, config, logger
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


# login api
@api.post("/login")
def login(
    *,
    req_body:LoginRequest=Body(...),
    request:Request
):
    
    """
    Authenticate the username and password / Authenticate the MS Auth Token
    """

    # create request id
    _id = request.state.session_code

    # extract email id
    _email_id = req_body.email_id

    # check if user is trying to login via ms auth
    logger.info(f"[{_id}] check if user is trying to login via ms auth")
    if req_body.msauth_token:
        # send ms auth token to nibss msauth url
        ms_auth_headers = {"authorization":req_body.msauth_token}
        logger.info(f"[{_id}] sending request to validate msauth token")
        response = requests.get(f"{config.nibss_msauth_advised_url}/{config.nibss_msauth_endpoint}?applicationName={config.nibss_msauth_app_name}", headers=ms_auth_headers)
        if response.status_code != status.HTTP_200_OK:
            # invalid credentials
            _response_message = "invalid credentials"
            response_data = response.json()
            logger.info(f"[{_id}] ms auth token not valid : {response_data.get('message',_response_message)}")
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
            _data = None
            _error = BaseError(error_message=response_data.get("message",_response_message))
            _status_code = status.HTTP_401_UNAUTHORIZED
            _content = _response(meta=_meta, data=_data, error=_error)
            return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
        else:
            logger.info(f"[{_id}] msauth token valid")
            # valid msasuth credentials
            response_data = response.json()
            _email_id = response_data.get("emails",{"emails":['']})[0]


    # create session with db
    logger.info(f"[{_id}] creating db connection")
    with database_client.Session() as session:

        # query the employee
        logger.info(f"[{_id}] query the employee table")
        employee_data = session.query(
            Employee
        ).options(
            selectinload(Employee.role), selectinload(Employee.company)
        ).filter(
            Employee.email_id == _email_id
        ).first()

        # check if employee exists / wrong password / is active (ie. is account disabled)
        logger.info(f"[{_id}] checking if employee exists / valid password / is not deactivated")
        if not employee_data or employee_data.password != req_body.password or not employee_data.is_active:
            
            logger.info(f"[{_id}] creating invalid credentials response")
            _response_message = "invalid credentials"
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
            _data = None
            _error = BaseError(error_message=_response_message)
            _status_code = status.HTTP_401_UNAUTHORIZED

        else:        

            # retrive all employee info and format the data
            logger.info(f"[{_id}] format retreived data")
            employee_data = Employee_MF.model_validate(employee_data).model_dump()

            # create jwt token
            logger.info(f"[{_id}] generate jwt token")
            jwt_token = generateJwtToken(
                exp=100000,
                uid=employee_data.get("employee_id"), # User ID
                cid=employee_data.get("company",{}).get("company_id"), # Company ID
                rid=employee_data.get("role",{}).get("role_id"), # Role ID
                sid=_id
            )

            logger.info(f"[{_id}] creating response data")
            _response = TokenResponse
            _meta = TokenMeta(_id=_id, successful=True, message="logged in", token=jwt_token)
            # _data = employee_data
            _data = None
            _error = None
            _status_code = status.HTTP_200_OK

            logger.info(f"[{_id}] storing jwt in redis")
            redis_client.set_data(key=jwt_token, value=employee_data.get("email_id"), ttl=100000)

    # construct response
    logger.info(f"[{_id}] constructing response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())


@api.post("/forgot_password")
def forgot_password(
    *,
    req_body:ForgotPasswordRequest=Body(...),
    request:Request
):
    """
    Send Verification Code to User if user forgot password
    """

    # Create request_id
    _id = request.state.session_code

    # create session with db
    logger.info(f"[{_id}] creating db connection")
    with database_client.Session() as session:

        # query the employee
        logger.info(f"[{_id}] query the employee table")
        employee_data = session.query(
            Employee
        ).filter(
            Employee.email_id == req_body.email_id
        ).first()

        # check if employee exists / is active
        logger.info(f"[{_id}] checking if employee exists / is not deactivated")
        if not employee_data or not employee_data.is_active:

            logger.info(f"[{_id}] creating invalid credentials response")
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message="invalid credentials")
            _data = None
            _error = BaseError(error_message="invalid credentials")
            _status_code = status.HTTP_401_UNAUTHORIZED
        else:
            # Create Verification code
            logger.info(f"[{_id}] creating verification code")
            verification_code = otp_client.create_verification_code(6)

            # Create Verification code Session in DB
            logger.info(f"[{_id}] storing verification code in db")
            otp_client.create_verification_code_session(session, VerificationCode, req_body.email_id, verification_code)
            
            # Send EMAIL
            logger.info(f"[{_id}] sending email")
            email_client.send_mail(req_body.email_id, "Verification Code", f"Your Verification Code: {verification_code}")

            logger.info(f"[{_id}] creating response data")
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=True, message="verification code sent")
            _data = None
            _error = None
            _status_code = status.HTTP_200_OK

    logger.info(f"[{_id}] creating response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())


@api.post("/reset_password")
def reset_password(
    *,
    req_body:ResetPasswordRequest = Body(...),
    request:Request
):
    """
    Update the password of the user if he passes in the correct verification code
    """

    # create request id
    _id = request.state.session_code

    # create session with db
    logger.info(f"[{_id}] creating db connection")
    with database_client.Session() as session:

        # query verification code
        logger.info(f"[{_id}] query the verification code table")
        verification_code_data = session.query(
            VerificationCode
        ).filter(
            VerificationCode.email_id == req_body.email_id
        ).first()

        # check if verification code is valid
        logger.info(f"[{_id}] check if verification code is valid")
        verification_code_is_expired = ( datetime.datetime.now(pytz.utc) - verification_code_data.create_date.astimezone(pytz.utc) > datetime.timedelta(minutes=5) )
        logger.debug(verification_code_is_expired)
        logger.debug(verification_code_data.create_date.astimezone(pytz.utc))
        logger.debug(datetime.datetime.now(pytz.utc) )
        logger.debug(datetime.datetime.now(pytz.utc) - verification_code_data.create_date.astimezone(pytz.utc) )
        if not verification_code_data or verification_code_is_expired or verification_code_data._code != req_body.code:

            logger.info(f"[{_id}] creating invalid credentials response")
            _response_message = "invalid credentials"
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
            _data = None
            _error = BaseError(error_message=_response_message)
            _status_code = status.HTTP_401_UNAUTHORIZED

        else:

            # query employee
            logger.info(f"[{_id}] querying employee")
            employee_data = session.query(
                Employee
            ).filter(
                Employee.email_id  == req_body.email_id
            ).first()

            # update password
            logger.info(f"[{_id}] changing password")
            employee_data.password = req_body.new_password

            # commit session
            logger.info(f"[{_id}] commiting change in db")
            session.commit()

            logger.info(f"[{_id}] creating response data")
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=True, message=f"password updated for {req_body.email_id}")
            _data = None
            _error = None
            _status_code = status.HTTP_200_OK

    logger.info(f"[{_id}] creating response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    

#############
## Profile ##
#############


@api.get("/roles")
def get_roles(
    *,
    x_verbose:bool=Header(False, alias="x-verbose"),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request
):
    
    """
    Return roles
    """
    # create request id
    _id = request.state.session_code
    # get role of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id = decoded_token.get("rid")

    # create session with db
    logger.info(f"[{_id}] creating db connection")
    with database_client.Session() as session:

        # creating the query
        logger.info(f"[{_id}] creating the query based on headers recieved")
        non_verbose_data = (Roles.role_name, Roles.public_id.label("role_id"))
        data_to_query = (Roles,) if x_verbose else non_verbose_data

        # query the db
        logger.info(f"[{_id}] query the db")
        role_data = session.query(*data_to_query)
        role_data = role_data.all() if role_id == PortalRole.SUPER_ADMIN.value else role_data.filter(Roles.public_id != PortalRole.SUPER_ADMIN.value).all()

        # format data
        logger.info(f"[{_id}] format the recieved data")
        role_data = [ Roles_MF.model_validate(i).model_dump() if x_verbose else i._asdict() for i in role_data ] 
    
    logger.info(f"[{_id}] create response data")
    _response = BaseResponse
    _meta = BaseMeta(_id=_id, successful=True, message="retrieved roles")
    _data = role_data
    _error = None
    _status_code = status.HTTP_200_OK

    logger.info(f"[{_id}] creating response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    
    
@api.get("/employees")
def get_all_employees(
    *,
    x_verbose:bool=Header(True, alias="x-verbose"),
    company_id:str=Query(...),
    page_no:int= Query(1),
    items_per_page:int= Query(15),
    search:str=Query(None),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")


    # check if non super admin + company_id == all or company_id != cid
    logger.info(f"[{_id}] check if user has permisson to use this api")
    if not (role_id != PortalRole.SUPER_ADMIN.value and (company_id != decoded_token.get("cid"))) and role_id in (_.value for _ in PortalRole)  :

        # create session with db
        logger.info(f"[{_id}] create connection to db")
        with database_client.Session() as session:

            # setup non verbose data
            logger.info(f"[{_id}] create query")
            non_verbose_data = (Employee.public_id.label("employee_id"), Employee.email_id, Employee.employee_name, Employee.phone_number)
            data_to_query = (Employee,) if x_verbose else non_verbose_data
            query_options = (joinedload(Employee.role), joinedload(Employee.company), ) if x_verbose else ()

            # basic query
            query = session.query( *data_to_query ).options( *query_options )

            if company_id != "all": 
                # filter by company id
                logger.info(f"[{_id}] add company filter to query")
                query = query.join(
                    Company,
                    Company.company_id == Employee.company_id
                ).filter(
                    Company.public_id == company_id
                )
            
            if search:
                logger.info(f"[{_id}] add full text search to query")
                query = query.filter(Employee.email_id.like(f"%{search}%"))

            # get total count for pagination
            logger.info(f"[{_id}] get toatl count of employees")
            total_count = session.query(func.count()).select_from(Employee).scalar()

            # pagination
            logger.info(f"[{_id}] add pagination to employees")
            offset = (page_no - 1) * items_per_page
            query = query.order_by(Employee.create_date).offset(offset).limit(items_per_page)

            # get all data
            logger.info(f"[{_id}] query db")
            employee_data = query.all()

            if employee_data:
                # format data
                logger.info(f"[{_id}] format retreived employee data")
                employee_data = [  Employee_MF.model_validate(i).model_dump() if x_verbose else i._asdict() for i in employee_data  ]
        
        logger.info(f"[{_id}] create response data")
        _response = PaginationResponse
        _pagination_data = PaginationData(items_per_page=items_per_page, page_no=page_no, total_count=total_count, page_url=request.url._url )
        _meta = PaginationMeta(_id=_id, successful=True, message=None, pagination_data=_pagination_data)
        _data = employee_data
        _error = None
        _status_code = status.HTTP_200_OK

    else:
        # create unauthorized response data
        logger.info(f"[{_id}] create unauthorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message= _response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN

    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    

@api.get("/employee/{employee_id}")
def get_employee(
    *,
    x_verbose:bool=Header(True, alias="x-verbose"),
    employee_id:str=Path(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request
):
    
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    logger.info(f"[{_id}] check if user is authorized to use this endpoint")
    if  role_id not in (_.value for _ in PortalRole)  :
        logger.info(f"[{_id}] create unauthorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN

    else:

        # create session with db
        logger.info(f"[{_id}] create db connection")
        with database_client.Session() as session:

            logger.info(f"[{_id}] create query")
            non_verbose_data = (Employee.public_id.label("employee_id"), Employee.email_id, Employee.employee_name, Employee.phone_number)
            data_to_query = (Employee,) if x_verbose else non_verbose_data
            query_options = (joinedload(Employee.role), joinedload(Employee.company), ) if x_verbose else ()

            query = session.query(
                *data_to_query
            ).options(
                *query_options
            )

            if role_id == PortalRole.SUPER_ADMIN.value:

                logger.info(f"[{_id}] add employee_id filter to query")
                query = query.filter(
                    Employee.public_id == employee_id
                )

            elif role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value:
                
                logger.info(f"[{_id}] add employee_id and company_id (from jwt) filter to query")
                query = query.join(
                    Company,
                    Company.company_id == Employee.company_id
                ).filter(
                    Employee.public_id == employee_id,
                    Company.public_id == decoded_token.get("cid")
                )

            logger.info(f"[{_id}] query db")
            employee_data = query.first()

            if employee_data:
                logger.info(f"[{_id}] format retreived data")
                employee_data = Employee_MF.model_validate(employee_data).model_dump() if x_verbose else employee_data._asdict()

                logger.info(f"[{_id}] create response data")
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message=None)
                _data = employee_data
                _error = None
                _status_code = status.HTTP_200_OK

                is_first_login = redis_client.get_data(key=f"NEW_{employee_data.get('employee_id')}")
                employee_data["is_first_login"] = True if is_first_login else False
                # redis_client.delete_key(f"NEW_{employee_data.get('employee_id')}")


            else:
                logger.info(f"[{_id}] create user not found response data")
                _response_message = "user not found"
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
                _data = None
                _error = BaseError(error_message=_response_message)
                _status_code = status.HTTP_404_NOT_FOUND


    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    

@api.post("/employee")
def create_employee(
    *,
    req_body:CreateEmployeeRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # create session with db
    logger.info(f"[{_id}] create db connection")
    with database_client.Session() as session:
        # query company
        logger.info(f"[{_id}] query company data")
        company_data = session.query(Company).filter(Company.public_id==req_body.company_id).first()
        # query role
        logger.info(f"[{_id}] query role data")
        role_data = session.query(Roles).filter(Roles.public_id==req_body.role_id).first()
        
        # cheeck if role is valid or admin using differnt cid
        logger.info(f"[{_id}] check if user is authorised to use this endpoint")
        if ( role_id not in (PortalRole.SUPER_ADMIN.value, PortalRole.ADMIN.value) ) or (role_id == PortalRole.ADMIN.value and decoded_token.get("cid") != company_data.public_id):
            logger.info(f"[{_id}] create unathorized response data")
            _response_message = "unauthorized"
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
            _data = None
            _error = BaseError(error_message=_response_message)
            _status_code = status.HTTP_403_FORBIDDEN

        else:
            # create employee object
            logger.info(f"[{_id}] create employee object")
            employee_data = Employee(
                email_id=req_body.email_id,
                password=req_body.password,
                employee_name=req_body.employee_name,
                phone_number=req_body.phone_number,
                employee_profile_pic=req_body.employee_profile_pic,
                company_id=company_data.company_id,
                role_id=role_data.role_id,
                is_active=True
            )

            try:
                # add employee to db
                logger.info(f"[{_id}] add employee to db")
                session.add(employee_data)
                session.commit()
                session.refresh(employee_data)
                
                logger.info(f"[{_id}] create response data")
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message="created")
                _data = Employee_MF.model_validate(employee_data).model_dump()
                _error = None
                _status_code = status.HTTP_200_OK

                logger.info(f"[{_id}] store employee data to redis")
                redis_client.set_data(key=f"NEW_{employee_data.public_id}", value=1, ttl=None)

                
            except sqlalchemy.exc.IntegrityError as e:

                logger.info(f"[{_id}] create: user exists data")
                _response_message = "user exists"
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
                _data = None
                _error = BaseError(error_message=_response_message)
                _status_code = status.HTTP_400_BAD_REQUEST

    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    

@api.put("/employee/{employee_id}")
def modify_employee(
    *,
    employee_id:str=Path(...),
    req_body:ModifyEmployeeDataRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request

):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if  role_id not in (_.value for _ in PortalRole) or  (role_id == PortalRole.EXPLORER.value and employee_id != decoded_token.get("uid")):
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN

    else:
        # create session with db
        logger.info(f"[{_id}] create db connection")
        with database_client.Session() as session:

            # create query
            logger.info(f"[{_id}] create query")
            query = session.query(
                Employee
            )
            
            # add employee_id filter to query
            if role_id == PortalRole.SUPER_ADMIN.value or role_id == PortalRole.EXPLORER.value:
                logger.info(f"[{_id}] add employee_id filter to query")
                employee_data = query.filter(
                    Employee.public_id == employee_id
                )

            # add employee_id and company_id (from jwt) filter to query
            elif role_id == PortalRole.ADMIN.value:
                logger.info(f"[{_id}] add employee_id and company_id (from jwt) filter to query")
                employee_data = query.join(
                    Company,
                    Employee.company_id == Company.company_id
                ).filter(
                    Employee.public_id == employee_id,
                    Company.public_id == decoded_token.get("cid")
                )

            # query db
            logger.info(f"[{_id}] query db")
            employee_data = employee_data.first()

            if not employee_data:
                # create user not found response data
                logger.info(f"[{_id}] create user not found response data")
                _response_message = "user not found"
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
                _data = None
                _error = BaseError(error_message=_response_message)
                _status_code = status.HTTP_404_NOT_FOUND
            else:
                # update data
                logger.info(f"[{_id}] update data")
                employee_data.employee_name = req_body.employee_name
                employee_data.phone_number = req_body.phone_number
                employee_data.employee_profile_pic = req_body.employee_profile_pic
                employee_data.is_active = req_body.is_active

                session.commit()
                session.refresh(employee_data)

                # format the employee object
                logger.info(f"[{_id}] format the employee object")
                employee_data = Employee_MF.model_validate(employee_data).model_dump()

                # create response data
                logger.info(f"[{_id}] create response data")
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message="updated")
                _data = employee_data
                _error = None
                _status_code = status.HTTP_200_OK

    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    

@api.put("/employee/{employee_id}/update_password")
def update_password(
    *,
    employee_id:str=Path(...),
    req_body:ModifyEmployeePasswordRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request
):
     # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if  role_id not in (_.value for _ in PortalRole) or  (role_id == PortalRole.EXPLORER.value and employee_id != decoded_token.get("uid")):
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN

    else:
        # create session with db
        logger.info(f"[{_id}] create db connection")
        with database_client.Session() as session:

            # create query
            logger.info(f"[{_id}] create query")
            query = session.query(
                Employee
            )
            
            if role_id == PortalRole.SUPER_ADMIN.value or role_id == PortalRole.EXPLORER.value:
                # add employee_id filter to query"
                logger.info(f"[{_id}] add employee_id filter to query")
                query = query.filter(
                    Employee.public_id == employee_id
                )

            elif role_id == PortalRole.ADMIN.value:
                # add employee_id and company_id (from jwt) filter to query
                logger.info(f"[{_id}] add employee_id and company_id (from jwt) filter to query")
                query = query.join(
                    Company,
                    Employee.company_id == Company.company_id
                ).filter(
                    Employee.public_id == employee_id,
                    Company.public_id == decoded_token.get("cid")
                )

            # query db
            logger.info(f"[{_id}] query db")
            employee_data = query.first()

            if not employee_data: 
                # create user not found response data
                logger.info(f"[{_id}] create user not found response data")
                _response_message = "user not found"
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
                _data = None
                _error = BaseError(error_message=_response_message)
                _status_code = status.HTTP_404_NOT_FOUND
            else:

                if role_id == PortalRole.EXPLORER.value and req_body.old_password != employee_data.password:
                    # create invalid credentials response data
                    logger.info(f"[{_id}] create invalid credentials response data")
                    _response_message = "invalid credentials"
                    _response = BaseResponse
                    _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
                    _data = None
                    _error = BaseError(error_message=_response_message)
                    _status_code = status.HTTP_403_FORBIDDEN
                elif req_body.new_password in (getattr(employee_data, f"password_old_{i}") for i in range(1, 13)) or req_body.new_password == employee_data.password:
                    # create 'cant update new password with old password' response data
                    logger.info(f"[{_id}] create 'cant update new password with old password' response data")
                    _response_message = "new password cannot be the same as old password"
                    _response = BaseResponse
                    _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
                    _data = None
                    _error = BaseError(error_message=_response_message)
                    _status_code = status.HTTP_403_FORBIDDEN
                else:
                    
                    # shift old password
                    logger.info(f"[{_id}] shift old password")
                    employee_data.password_old_12 = employee_data.password_old_11
                    employee_data.password_old_11 = employee_data.password_old_10
                    employee_data.password_old_10 = employee_data.password_old_9
                    employee_data.password_old_9 = employee_data.password_old_8
                    employee_data.password_old_8 = employee_data.password_old_7
                    employee_data.password_old_7 = employee_data.password_old_6
                    employee_data.password_old_6 = employee_data.password_old_5
                    employee_data.password_old_5 = employee_data.password_old_4
                    employee_data.password_old_4 = employee_data.password_old_3
                    employee_data.password_old_3 = employee_data.password_old_2
                    employee_data.password_old_2 = employee_data.password_old_1
                    employee_data.password_old_1 = employee_data.password

                    # update password 
                    logger.info(f"[{_id}] update password")
                    employee_data.password = req_body.new_password
                    session.commit()

                    # create response message
                    logger.info(f"[{_id}] create response message")
                    _response = BaseResponse
                    _meta = BaseMeta(_id=_id, successful=True, message="updated")
                    _data = None
                    _error = None
                    _status_code = status.HTTP_200_OK

                # delete first login flag from redis
                logger.info(f"[{_id}] delete first login flag from redis")
                redis_client.delete_key(f"NEW_{employee_data.public_id}")

    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    
@api.delete("/employee/{employee_id}")
def delete_employee(
    *,
    employee_id:str=Path(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request
):
     # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if  role_id not in (PortalRole.SUPER_ADMIN.value, PortalRole.ADMIN.value) :
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN

    else:
        # create session with db
        logger.info(f"[{_id}] create db connection")
        with database_client.Session() as session:

            # create query
            logger.info(f"[{_id}] create query")
            query = session.query(
                Employee
            )
            
    
            # add employee_id filter to query
            if role_id == PortalRole.SUPER_ADMIN.value:
                logger.info(f"[{_id}] add employee_id filter to query")
                query = query.filter(
                    Employee.public_id == employee_id
                )

            # add employee_id and company_id (from jwt) filter to query
            elif role_id == PortalRole.ADMIN.value:
                logger.info(f"[{_id}] add employee_id and company_id (from jwt) filter to query")
                query = query.join(
                    Company,
                    Employee.company_id == Company.company_id
                ).filter(
                    Employee.public_id == employee_id,
                    Company.public_id == decoded_token.get("cid")
                )

            # query db
            logger.info(f"[{_id}] query db")
            employee_data = query.first()

            if not employee_data:
                # create employee not found response data
                logger.info(f"[{_id}] create employee not found response data")
                _response_message = "user not found"
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
                _data = None
                _error = BaseError(error_message=_response_message)
                _status_code = status.HTTP_404_NOT_FOUND
            else:
                #  delete employee
                logger.info(f"[{_id}] delete employee")
                session.delete(employee_data)
                session.commit()
                
                #  delete employee
                logger.info(f"[{_id}] create response data")
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message="deleted")
                _data = None
                _error = None
                _status_code = status.HTTP_200_OK

    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    

###############
## Dashboard ##
###############

# Logs
@api.get("/nface_logs")
def get_nface_logs(
    *,
    x_verbose:bool=Header(True, alias="x-verbose"),
    x_ignore_pagination:bool=Header(False, alias="x-ignore-pagination"),
    x_response_type:str=Header("json",alias="x-response-type"), # json/ csv/ csv-transaction

    company_id:str=Query(...),
    status_filter:str=Query(...), # success, all, failure, issue
    service_filter:str=Query(...), # face_comparison , all , passive_liveness
    start_datetime:datetime.datetime = Query(...),
    end_datetime:datetime.datetime = Query(...),
    page_no:int = Query(1),
    items_per_page:int = Query(15),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if  role_id not in (_.value for _ in PortalRole) or  ( (role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value) and (company_id != decoded_token.get("cid") or company_id=="all") ):
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN

    else:

        # create session with db
        logger.info(f"[{_id}] create db connection")
        with database_client.Session() as session:
            
            # create query
            logger.info(f"[{_id}] create query")
            query = session.query(
                NFaceLogs
            )

            if company_id != "all":
                # add company_id filter to query
                logger.info(f"[{_id}] add company_id filter to query")
                query = query.join(
                    Company,
                    Company.company_id == NFaceLogs.company_id
                ).filter(
                    Company.public_id == company_id
                )
            

            if status_filter != "all":
                # add status filter to query
                logger.info(f"[{_id}] add status filter to query")
                query = query.join(
                    StatusMaster,
                    StatusMaster.status_id == NFaceLogs.status_id
                ).filter(StatusMaster.status == status_filter.upper().strip())


            if service_filter != "all":
                # add service filter to query
                logger.info(f"[{_id}] add service filter to query")
                query = query.join(
                    ServiceMaster,
                    ServiceMaster.service_id == NFaceLogs.service_id
                ).filter(ServiceMaster.service_name == service_filter.upper().strip())


            # add datetime filter to query
            logger.info(f"[{_id}] add datetime filter to query")
            logger.debug(NFaceLogs)
            logger.debug(NFaceLogs.create_date)
            query = query.filter(NFaceLogs.create_date >= start_datetime,
                                    NFaceLogs.create_date <= end_datetime)
            
            

            # find total count of logs
            logger.info(f"[{_id}] find total count of logs")
            total_count = session.query(func.count()).select_from(NFaceLogs).scalar()


            # Pagination
            if not x_ignore_pagination:
                logger.info(f"[{_id}] add pagination to query")
                offset = (page_no - 1) * items_per_page
                query = query.order_by(NFaceLogs.create_date).offset(offset).limit(items_per_page)

            # query db
            logger.info(f"[{_id}] query db")
            log_data = query.all()
            logger.debug(log_data)

            # format retrieved data
            logger.info(f"[{_id}] format retrieved data")
            log_data = [ NFaceLogs_MF.model_validate(_).model_dump() for _ in log_data ]

            # create response data
            logger.info(f"[{_id}] create response data")
            _response = PaginationResponse
            _pagination_data = PaginationData(items_per_page=items_per_page, page_no=page_no, total_count=total_count, page_url=request.url._url )
            _meta = PaginationMeta(_id=_id, successful=True, message=None, pagination_data=_pagination_data)
            _data = log_data
            _error = None
            _status_code = status.HTTP_200_OK

    if x_response_type == "json":

        logger.info(f"[{_id}] create json response")
        _content = _response(meta=_meta, data=_data, error=_error)
        return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
        
    elif x_response_type == "csv" or x_response_type == "excel":
        
        # create excel response data
        logger.info(f"[{_id}] create excel response data")

        csv_data = io.StringIO()
        logger.debug(log_data)
        csv_writer = csv.DictWriter(csv_data, fieldnames=log_data[0].keys())
        csv_writer.writeheader()
        csv_writer.writerows(log_data)

        # Create a streaming response
        response = StreamingResponse(iter([csv_data.getvalue()]), media_type="text/csv")
        response.headers["Content-Disposition"] = "attachment;filename=output.csv"
        return response
        

    elif x_response_type == "csv-transaction" or x_response_type == "transaction-excel":
    
        
        columns = ["Transaction ID/Ref","Sending_institution","Beneficiary_institution","Terminal", "Transaction Type","Transaction Amount", "Fee", "VAT Fee", "Platform Fee", "Sending_bank fee", "Beneficiary Bank Fee", "Introducer fee", "Transaction Date", "Sender Account Name", "Sender Account Number", "Beneficiary Account Name", "Beneficiary Account Number"]

        formatted_date = end_datetime.strftime("%Y%m%d")


        # Initialize a list to store rows
        data = []

        # Populate the data list with rows
        logger.info(f"[{_id}] populate the data list with rows")
        for idx, row in enumerate(log_data):

            transaction_id_ref = row.get("session_code")
            sending_institution = row.get("company",{}).get("company_name")
            beneficiary_institution = "NIBSS"
            terminal = None
            transaction_type = "CR"

            if ( row.get("service",{}).get("service_name") == "PASSIVE_LIVENESS" and row.get("status",{}).get("status") != "ISSUE"):
                transaction_amount = 50
            elif ( row.get("service",{}).get("service_name") == "FACE_COMPARISON" and row.get("status",{}).get("status") != "ISSUE"):
                transaction_amount = 10
            else:
                transaction_amount = 0

            # fee = ...
            vat_fee = row.get("company",{}).get("billing_information",{}).get("vat", 0)
            platform_fee = 0
            sending_bank_fee = 0
            beneficiary_bank_fee = 0
            introducer_fee = 0
            fee = transaction_amount + (vat_fee*transaction_amount)
            transaction_date = row.get("create_date",None)
            sender_account_name = row.get("company",{}).get("banking_information",{}).get("billing_account_name")
            sender_account_number = row.get("company",{}).get("banking_information",{}).get("billing_account_number")
            beneficiary_account_name = "NIBSS"
            beneficiary_account_number = None

            data.append([transaction_id_ref, sending_institution, beneficiary_institution, terminal, transaction_type, transaction_amount, fee, vat_fee, platform_fee, sending_bank_fee, beneficiary_bank_fee, introducer_fee, transaction_date, sender_account_name, sender_account_number, beneficiary_account_name, beneficiary_account_number])

        # Create a DataFrame from the data and columns
        logger.info(f"[{_id}] Create a DataFrame from the data and columns")
        df = pd.DataFrame(data, columns=columns)

        # Specify the Excel file name
        excel_file_name = f"N-Face_Billing_Transaction_details_{formatted_date}.xlsx"

        # Write the DataFrame to an Excel file
        logger.info(f"[{_id}] Write the DataFrame to an Excel file")
        excel_bytes = io.BytesIO()
        df.to_excel(excel_bytes, index=False)


        # Create a streaming response for the Excel file
        logger.info(f"[{_id}] Create a streaming response for the Excel file")
        response = StreamingResponse(iter([excel_bytes.getvalue()]), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        response.headers["Content-Disposition"] = f"attachment;filename={excel_file_name}"

        # Optionally, close the file to free up resources
        excel_bytes.close()

        # Return the streaming response
        return response
        

# Stats
@api.get("/nface_logs/stats")
def get_nface_stats(
    *,
    company_id:str=Query(...), # all / company_id
    start_datetime:datetime.datetime = Query(...),
    end_datetime:datetime.datetime = Query(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if  role_id not in (_.value for _ in PortalRole) or  ( (role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value) and (company_id != decoded_token.get("cid") or company_id=="all") ):
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN
    else:

        # create session with db
        logger.info(f"[{_id}] create db connection")
        with database_client.Session() as session:
            
            # create query
            logger.info(f"[{_id}] create query")
            query = session.query(
                ServiceMaster.service_name,
                StatusMaster.status,
                func.count().label('count')
            ).join(
                NFaceLogs,
                StatusMaster.status_id==NFaceLogs.status_id
            ).join(
                ServiceMaster,
                ServiceMaster.service_id==NFaceLogs.service_id
            )


            if company_id != "all":
                # add company_id filter to query
                logger.info(f"[{_id}] add company_id filter to query")
                query = query.join(
                    Company,
                    Company.company_id == NFaceLogs.company_id
                ).filter(
                    Company.public_id == company_id
                )

            # add datetime filter to query
            logger.info(f"[{_id}] add datetime filter to query")
            query = query.filter(
                NFaceLogs.create_date >= start_datetime,
                NFaceLogs.create_date <= end_datetime
            )

            # Add grouping and ordering
            logger.info(f"[{_id}] add groupby filter to query")
            query = query.group_by(ServiceMaster.service_name, StatusMaster.status,)

            # restructure retrieved data
            logger.info(f"[{_id}] restructure retrieved data")
            stat_dict = lambda x : {"FAILURE":x.get("FAILURE",0),"SUCCESS":x.get("SUCCESS",0),"ISSUE":x.get("ISSUE",0)}
            query = query.all()
            if query:
                nested_dict = {}
                for outer_key, inner_key, value in query:
                    if outer_key not in nested_dict:
                        nested_dict[outer_key] = {}
                    nested_dict[outer_key][inner_key] = value

            for k,v in nested_dict.items():
                nested_dict[k] = stat_dict(v)

            # create response data
            logger.info(f"[{_id}] create response data")
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=True, message=None)
            _data = nested_dict
            _error = None
            _status_code = status.HTTP_200_OK

    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())


# Invoice
@api.get("/invoice")
def get_invoice(
    *,
    x_ignore_pagination:bool=Header(False, alias="x-ignore-pagination"),
    x_response_type:str=Header("json",alias="x-response-type"), # json/ csv/ excel

    company_id:str=Query("all"),
    bank_type_filter:str=Query("all"), # all dbm non dmb
    status_filter:str=Query("all"), # pending, all, paid
    start_datetime:datetime.datetime = Query(...),
    end_datetime:datetime.datetime = Query(...),
    page_no:int= Query(1),
    items_per_page:int= Query(15),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if (role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value) or (company_id != "all" and role_id != PortalRole.SUPER_ADMIN.value ):
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN
    else:
        # create session with db
        logger.info(f"[{_id}] create db connection")
        with database_client.Session() as session:
            
            # create query
            logger.info(f"[{_id}] create query")
            query = session.query(
                Invoice,
                BankTypeMaster.bank_type
            ).join(
                CompanyBankingInfo,
                CompanyBankingInfo.company_id==Invoice.company_id
            ).join(
                BankTypeMaster,
                BankTypeMaster.bank_type_id == CompanyBankingInfo.bank_type_id
            )

            # add bank type filter to query
            if bank_type_filter != "all":
                logger.info(f"[{_id}] add bank type filter to query")
                query = query.filter(BankTypeMaster.bank_type == bank_type_filter.upper().strip())

            # add company id filter to query
            if company_id != "all":
                logger.info(f"[{_id}] add company id filter to query")
                query = query.join(Company, Company.company_id == Invoice.company_id).filter(Company.public_id == company_id)


            # add status filter to query
            if status_filter != "all":
                logger.info(f"[{_id}] add status filter to query")
                sf = 1 if status_filter.upper().strip() == "PAID" else 0
                query = query.filter(Invoice.payment_status == sf)
            
            # add datetime filter to query
            logger.info(f"[{_id}] add datetime filter to query")
            query = query.filter(Invoice.end_date >= start_datetime,
                                    Invoice.end_date <= end_datetime)
            logger.debug("done")
            # add pagination to query
            if not x_ignore_pagination:
                logger.info(f"[{_id}] add pagination to query")
                offset = (page_no - 1) * items_per_page
                query = query.order_by(Invoice.end_date).offset(offset).limit(items_per_page)

            # query db
            logger.info(f"[{_id}] query db")
            invoice_data = query.all()

            if invoice_data:
                # format data
                logger.info(f"[{_id}] format retreived invoice_data")
                invoice_data = [  Invoice_MF.model_validate(i).model_dump() for i in invoice_data  ]
            
        if x_response_type == "json":
            logger.info(f"[{_id}] create response data")

            _response_message = None
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=True, message=_response_message)
            _data = invoice_data
            _error = None
            _status_code = status.HTTP_200_OK

        elif x_response_type == "csv":
            
            # Extract all billing dates from the query
            logger.info(f"[{_id}] extract all billing dates from the query")
            billing_dates = [row.get("end_date") for row in invoice_data if row.get("end_date")]

            # Find the maximum billing date
            logger.info(f"[{_id}] find the maximum billing date")
            max_billing_date = max(billing_dates) if billing_dates else None

            # Define the TXT file name with the formatted date
            logger.info(f"[{_id}] define the TXT file name with the formatted date")
            if max_billing_date:
                formatted_date = datetime.datetime.strptime(max_billing_date, "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d")
                txt_file_name = f"N-Face_Billing_Smartdet_{formatted_date}.txt"
            else:
                formatted_date = ""
                txt_file_name = "N-Face_Billing_Smartdet.txt"

            max_billing_date = max(billing_dates) if billing_dates else None

            # Check bank_type_filter
            logger.info(f"[{_id}] check bank_type_filter")
            
            if bank_type_filter.lower().strip() == "all":
                dmb_columns = ["Routing_Number","product_code","Billing_date","Amount"]
                non_dmb_columns = ["Serial_No","Account_Number","Sort_Code","Payee_Beneficiary", "Amount", "Narration", "Payer", "Debit_Sort_Code", "Merchant_ID",  "CRDR", "Currency", "Cust_Code", "Beneficiary_BVN", "Payer_BVN", "Billing_Date"]

                dmb_data = []
                non_dmb_data = []
                # Check bank_type_filter
                logger.info(f"[{_id}] separate relavent dmb and non dmb data")
                for idx, row in enumerate(invoice_data):
                    #DMB DATA
                    if row.get("bank_type").lower() == "dmb":
                        routing_number = row.get("company",{}).get("banking_information",{}).get("routing_number",None)
                        product_code = row.get("company",{}).get("banking_information",{}).get("product_code",None)
                        billing_date = row.get("end_date",None)
                        amount = float(row.get("amount",0))

                        # Convert the date to the desired format ("yyyymmdd")
                        formatted_billing_date = datetime.datetime.strptime(billing_date, "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d")
                        dmb_data.append([routing_number,product_code,formatted_billing_date,amount])

                    elif row.get("bank_type").lower() == "non-dmb":
                        #NON DMMB DATA
                        serial_no = idx + 1
                        account_number = row.get("company", {}).get("banking_information", {}).get("billing_account_number", None)
                        sort_code = row.get("company", {}).get("banking_information", {}).get("sort_code", None)
                        payee_beneficiary = row.get("company", {}).get("banking_information", {}).get("payee_beneficiary", None)
                        amount = float(row.get("amount", 0))
                        narration = "N-Face Billing"
                        payer = "NIBSS PLC"
                        debit_sort_code = ""
                        merchant_id = ""
                        crdr = "DR"
                        currency = "NGN"
                        cust_code = ""
                        beneficiary_bvn = ""
                        payer_bvn = ""
                        billing_date = row.get("end_date", None)

                        non_dmb_data.append([serial_no, account_number, sort_code, payee_beneficiary, amount, narration, payer,
                                debit_sort_code, merchant_id, crdr, currency, cust_code, beneficiary_bvn, payer_bvn, billing_date])



                # create dmb and non dmb df
                logger.info(f"[{_id}] create dmb and non dmb dfs")
                dmb_df = pd.DataFrame(dmb_data, columns=dmb_columns)
                non_dmb_df = pd.DataFrame(non_dmb_data, columns=non_dmb_columns)
                
                # Write both DataFrames to an Excel file with separate sheets
                logger.info(f"[{_id}] Write both dataframes to an Excel file with separate sheets")
                excel_bytes = io.BytesIO()
                with pd.ExcelWriter(excel_bytes, engine='xlsxwriter') as writer:
                    dmb_df.to_excel(writer, sheet_name='DMB', index=False)
                    non_dmb_df.to_excel(writer, sheet_name='NON-DMB', index=False)

                # Create a streaming response for the Excel file
                logger.info(f"[{_id}] Create a streaming response for the Excel file")
                response = StreamingResponse(iter([excel_bytes.getvalue()]), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                response.headers["Content-Disposition"] = "attachment;filename=output.xlsx"

                # Optionally, close the BytesIO object to free up resources
                excel_bytes.close()

                # Return the streaming response
                return response

            elif bank_type_filter.lower().strip() == "dmb":

                # Define the columns
                columns = ["Routing_Number", "product_code", "Billing_date", "Amount"]
                
                # Create a BytesIO object to store the text data as bytes
                txt_data = io.BytesIO()
                
                # Write the header line with tab-separated column names
                logger.info(f"[{_id}] Write the header line with tab-separated column names")
                txt_data.write('\t'.join(columns).encode() + b'\n')
                
                # Write data to the BytesIO object and collect it in a list for future reference
                logger.info(f"[{_id}] Write data to the BytesIO object")
                data = []
                for row in invoice_data:
                    routing_number = row.get("company", {}).get("banking_information", {}).get("routing_number", None)
                    product_code = row.get("company", {}).get("banking_information", {}).get("product_code", None)
                    billing_date = row.get("end_date", None)
                    amount = float(row.get("amount", 0))

                    # Convert the date to the desired format ("yyyymmdd")
                    formatted_billing_date = datetime.datetime.strptime(billing_date, "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d")

                    # Write the data to the BytesIO object with tab-separated values
                    row_data = f"{routing_number}\t{product_code}\t{formatted_billing_date}\t{amount}\n".encode()
                    txt_data.write(row_data)
                    data.append([routing_number, product_code, formatted_billing_date, amount])

                # Reset the pointer to the beginning of the BytesIO object
                logger.info(f"[{_id}] Reset the pointer to the beginning of the BytesIO object")
                txt_data.seek(0)

                # Create a streaming response for the TXT file
                logger.info(f"[{_id}] Create a streaming response for the TXT file")
                response = StreamingResponse(iter([txt_data.getvalue()]), media_type="text/plain")
                response.headers["Content-Disposition"] = "attachment;filename=output.txt"

                # Optionally, close the BytesIO object to free up resources
                txt_data.close()

                # Return the streaming response
                return response

            elif bank_type_filter.lower().strip() == "non-dmb":
                
                columns = ["Serial_No","Account_Number","Sort_Code","Payee_Beneficiary", "Amount", "Narration", "Payer", "Debit_Sort_Code", "Merchant_ID",  "CRDR", "Currency", "Cust_Code", "Beneficiary_BVN", "Payer_BVN", "Billing_Date"]

                # Initialize a list to store rows
                data = []

                # Populate the data list with rows
                logger.info(f"[{_id}] populate the data list with rows")
                for idx, row in enumerate(query):
                    serial_no = idx + 1
                    account_number = row.get("company", {}).get("banking_information", {}).get("billing_account_number", None)
                    sort_code = row.get("company", {}).get("banking_information", {}).get("sort_code", None)
                    payee_beneficiary = row.get("company", {}).get("banking_information", {}).get("payee_beneficiary", None)
                    amount = float(row.get("amount", 0))
                    narration = "N-Face Billing"
                    payer = "NIBSS PLC"
                    debit_sort_code = ""
                    merchant_id = ""
                    crdr = "DR"
                    currency = "NGN"
                    cust_code = ""
                    beneficiary_bvn = ""
                    payer_bvn = ""
                    billing_date = row.get("end_date", None)

                    data.append([serial_no, account_number, sort_code, payee_beneficiary, amount, narration, payer,
                                debit_sort_code, merchant_id, crdr, currency, cust_code, beneficiary_bvn, payer_bvn, billing_date])


                # Create a DataFrame from the data and columns
                logger.info(f"[{_id}] Create a DataFrame from the data and columns")
                df = pd.DataFrame(data, columns=columns)

                # Convert the DataFrame to Excel format as bytes
                logger.info(f"[{_id}] Convert the DataFrame to Excel format as bytes")
                excel_bytes = io.BytesIO()
                df.to_excel(excel_bytes, index=False)

                # Create a streaming response for the Excel file
                logger.info(f"[{_id}] Create a streaming response for the Excel file")
                response = StreamingResponse(iter([excel_bytes.getvalue()]), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                response.headers["Content-Disposition"] = f"attachment;filename=N-Face_Billing_OFI_{formatted_date}.xlsx"

                # Optionally, close the BytesIO object to free up resources
                excel_bytes.close()

                # Return the streaming response
                return response

    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())


# Invoice
@api.get("/invoice/stats")
def get_invoice_stats(
    *,
    company_id:str=Query("all"),
    start_datetime:datetime.datetime = Query(...),
    end_datetime:datetime.datetime = Query(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request
):
    
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if (role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value) or (company_id != "all" and role_id != PortalRole.SUPER_ADMIN.value ):
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN
    else:
        # create session with db
        logger.info(f"[{_id}] create db connection")
        with database_client.Session() as session:

            # create query
            logger.info(f"[{_id}] create query")
            query = session.query(
                Invoice.payment_status,
                func.count(Invoice.payment_status).label('count'),
                func.sum(Invoice.amount).label('total_amount')
            )


            if company_id != "all":
                # add company filter to query
                logger.info(f"[{_id}] add company filter to query")
                query = query.join(Company, Company.company_id == Invoice.company_id).filter(Company.public_id == company_id)


            # add datetime filter to query
            logger.info(f"[{_id}] add datetime filter to query")
            query = query.filter(NFaceLogs.create_date >= start_datetime,
                                    NFaceLogs.create_date <= end_datetime)

            # add groupby payment_status to query
            logger.info(f"[{_id}] add groupby payment_status to query")
            query = query.group_by(Invoice.payment_status)

            # query db
            logger.info(f"[{_id}] query db")
            stats_data = query.all()

            # reformat data
            nested_dict = {}
            if stats_data:
                logger.info(f"[{_id}] reformat data")
                for _status, _count, _amount in stats_data:
                    _status_name = "PAID" if _status == 1 else "PENDING"
                    nested_dict[_status_name] = {}
                    nested_dict[_status_name]["total_count"] = _count
                    nested_dict[_status_name]["total_amount"] = _amount

        # create response data
        logger.info(f"[{_id}] create response data")
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=True, message=None)
        _data = nested_dict
        _error = None
        _status_code = status.HTTP_200_OK

    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
        

####################
## Control Center ##
####################

@api.get("/bank_type")
def bank_type(
    *,
    x_verbose:bool=Header(True, alias="x-verbose"),

    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value:
        # create unathorized response data
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN
    else:

        # check if user has permission to use this endpoint
        logger.info(f"[{_id}] check if user has permission to use this endpoint")
        with database_client.Session() as session:

            # create query
            logger.info(f"[{_id}] create query")
            non_verbose_data = (BankTypeMaster.public_id, BankTypeMaster.bank_type,)
            data_to_query = (BankTypeMaster,) if x_verbose else non_verbose_data

            bank_type_data = session.query(
                *data_to_query
            )

            # query db
            logger.info(f"[{_id}] query db")
            bank_type_data = bank_type_data.all()

            if bank_type_data:
                # format data
                logger.info(f"[{_id}] format retreived bank type data")
                bank_type_data = [  BankType_MF.model_validate(i).model_dump() if x_verbose else i._asdict() for i in bank_type_data  ]
        
            # create response data
            logger.info(f"[{_id}] create response data")
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=True, message=None)
            _data = bank_type_data
            _error = None
            _status_code = status.HTTP_200_OK

    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    
@api.get("/billing_frequency")
def billing_frequency(
    *,
    x_verbose:bool=Header(True, alias="x-verbose"),

    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value:
        # create unathorized response data
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN
    else:

        # check if user has permission to use this endpoint
        logger.info(f"[{_id}] check if user has permission to use this endpoint")
        with database_client.Session() as session:

            # create query
            logger.info(f"[{_id}] create query")
            non_verbose_data = (BillingFrequencyMaster.public_id, BillingFrequencyMaster.billing_frequency,)
            data_to_query = (BillingFrequencyMaster,) if x_verbose else non_verbose_data

            billing_frequency_data = session.query(
                *data_to_query
            )

            # query db
            logger.info(f"[{_id}] query db")
            billing_frequency_data = billing_frequency_data.all()

            if billing_frequency_data:
                # format data
                logger.info(f"[{_id}] format billing_frequency_data data")
                billing_frequency_data = [  BillingFrequency_MF.model_validate(i).model_dump() if x_verbose else i._asdict() for i in billing_frequency_data  ]
    
            # create response data
            logger.info(f"[{_id}] create response data")
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=True, message=None)
            _data = billing_frequency_data
            _error = None
            _status_code = status.HTTP_200_OK

    
    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    

@api.get("/billing_mode_type")
def billing_mode_type(
    *,
    x_verbose:bool=Header(True, alias="x-verbose"),

    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value:
        # create unathorized response data
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN
    else:

        # check if user has permission to use this endpoint
        logger.info(f"[{_id}] check if user has permission to use this endpoint")
        with database_client.Session() as session:

            # create query
            logger.info(f"[{_id}] create query")
            non_verbose_data = (BillingModeTypeMaster.public_id, BillingModeTypeMaster.billing_mode_type,)
            data_to_query = (BillingModeTypeMaster,) if x_verbose else non_verbose_data

            billing_mode_data = session.query(
                *data_to_query
            )

            # query db
            logger.info(f"[{_id}] query db")
            billing_mode_data = billing_mode_data.all()

            if billing_mode_data:
                # format data
                logger.info(f"[{_id}] format billing_mode_data type data")
                billing_mode_data = [  BillingMode_MF.model_validate(i).model_dump() if x_verbose else i._asdict() for i in billing_mode_data  ]
        
            # create response data
            logger.info(f"[{_id}] create response data")
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=True, message=None)
            _data = billing_mode_data
            _error = None
            _status_code = status.HTTP_200_OK
    
    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    

# CRUD Company

# Read Company
@api.get("/company")
def get_all_companies(
    *,
    x_verbose:bool=Header(True, alias="x-verbose"),
    x_ignore_pagination:bool=Header(False, alias="x-ignore-pagination"),

    page_no:int= Query(1),
    items_per_page:int= Query(15),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value:
        # create unathorized response data
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN
    else:

        # check if user has permission to use this endpoint
        logger.info(f"[{_id}] check if user has permission to use this endpoint")
        with database_client.Session() as session:


            # create query
            logger.info(f"[{_id}] create query")
            non_verbose_data = (Company.public_id, Company.company_name,)
            data_to_query = (Company,) if x_verbose else non_verbose_data

            company_data = session.query(
                *data_to_query
            )

            # calculate total companies
            logger.info(f"[{_id}] calculate total companies")
            total_count = company_data.with_entities(func.count()).scalar()
            
            # Pagination
            if not x_ignore_pagination:
                logger.info(f"[{_id}] add pagination to query")
                offset = (page_no - 1) * items_per_page
                company_data = company_data.order_by(Company.create_date).offset(offset).limit(items_per_page)

            # query db
            logger.info(f"[{_id}] query db")
            company_data = company_data.all()
            if company_data:
                # format data
                logger.info(f"[{_id}] format data")
                company_data = [Company_MF.model_validate(i).model_dump() for i in company_data] if x_verbose else [i._asdict() for i in company_data]

            # create response data
            logger.info(f"[{_id}] create response data")
            _response = PaginationResponse
            _pagination_data = PaginationData(items_per_page=items_per_page, page_no=page_no, total_count=total_count, page_url=request.url._url )
            _meta = PaginationMeta(_id=_id, successful=True, message=None, pagination_data=_pagination_data)
            _data = company_data
            _error = None
            _status_code = status.HTTP_200_OK

    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    
@api.get("/company/{company_id}")
def get_company(
    *,
    x_verbose:bool=Header(True, alias="x-verbose"),

    company_id:str=Path(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value:
        # create unathorized response data
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN
    else:

        # check if user has permission to use this endpoint
        logger.info(f"[{_id}] check if user has permission to use this endpoint")
        with database_client.Session() as session:

            # create query
            logger.info(f"[{_id}] create query")
            non_verbose_data = (Company.public_id, Company.company_name,)
            data_to_query = (Company,) if x_verbose else non_verbose_data

            company_data = session.query(
                *data_to_query
            ).filter(
                Company.public_id==company_id
            )

            # query db
            logger.info(f"[{_id}] query db")
            company_data = company_data.all()
            if company_data:
                # format data
                logger.info(f"[{_id}] format data")
                company_data = [Company_MF.model_validate(i).model_dump() for i in company_data] if x_verbose else [i._asdict() for i in company_data]

                # create response data
                logger.info(f"[{_id}] create response data")
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message=None)
                _data = company_data
                _error = None
                _status_code = status.HTTP_200_OK

            else:
                # create company not found response data
                logger.info(f"[{_id}] create company not found response data")
                _response_message = "company not found"
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
                _data = None
                _error = BaseError(error_message=_response_message)
                _status_code = status.HTTP_404_NOT_FOUND
    
    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    
# Onboard Client
@api.post("/register_client")
def onboard_client(
    *,
    req_body:RegisterClientRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value:
        # create unathorized response data
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN
    else:

        # check if user has permission to use this endpoint
        logger.info(f"[{_id}] check if user has permission to use this endpoint")
        with database_client.Session() as session:

            # create company obj
            logger.info(f"[{_id}] create company obj")
            company_data = Company(
                company_name=req_body.company_name,
                is_active=True,
                client_id=req_body.client_id,
                auto_disable_days=req_body.auto_disable_days,
            )

            # add company to db
            logger.info(f"[{_id}] add company to db")
            session.add(company_data)


            try:
                # flush data
                logger.info(f"[{_id}] flush data")
                session.flush()
            except sqlalchemy.exc.IntegrityError as e:
                # create company/client_id exists response data
                logger.info(f"[{_id}] create company/client_id exists response data")
                _response_message = "company/client_id exists"
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
                _data = None
                _error = BaseError(error_message=_response_message)
                _status_code = status.HTTP_400_BAD_REQUEST
    
                # create response
                logger.info(f"[{_id}] create response")
                _content = _response(meta=_meta, data=_data, error=_error)
                return ORJSONResponse(status_code=_status_code, content=_content.model_dump())

            # load billing data
            logger.info(f"[{_id}] load billing data")
            billing_frequency_data = session.query(
                BillingFrequencyMaster
            ).filter(
                BillingFrequencyMaster.public_id==req_body.billing_frequency_id
            ).first()

            # load billing mode data
            logger.info(f"[{_id}] load billing mode data")
            billing_mode_type_data = session.query(
                BillingModeTypeMaster
            ).filter(
                BillingModeTypeMaster.public_id==req_body.billing_mode_type_id
            ).first()

            # load institution data
            logger.info(f"[{_id}] load institution data")
            institution_data = session.query(
                Institution
            ).filter(
                Institution.public_id==req_body.institution_id
            ).first()

            # create billing info obj
            logger.info(f"[{_id}] create billing info obj")
            billing_data = BillingInformation(
                email_id1=req_body.email_id,
                floor_cost=req_body.floor_cost,
                currency_id=1,
                billing_start_date=req_body.billing_start_date,
                billing_end_date=req_body.billing_end_date,
                billing_frequency_id=billing_frequency_data.billing_frequency_id,
                vat=req_body.vat,
                billing_mode_type_id=billing_mode_type_data.billing_mode_type_id,
                institution_id= institution_data.institution_id if institution_data else None,
                company_id=company_data.company_id
            )

            # ad billing info data to db
            logger.info(f"[{_id}] add billing info data to db")
            session.add(billing_data)

            if billing_mode_type_data.billing_mode_type == "PREPAID":
                # create wallet obj
                logger.info(f"[{_id}] create wallet obj")
                wallet_data = Wallet(
                    company_id = company_data.company_id,
                    amount = 0.0,
                    ledger_amount = 0.0,
                )
                # add wallet obj to db
                logger.info(f"[{_id}] add wallet obj to db")
                session.add(wallet_data)

            # load bank tyoe data from db
            logger.info(f"[{_id}] load bank tyoe data from db")
            bank_type_data = session.query(
                BankTypeMaster
            ).filter(
                BankTypeMaster.public_id==req_body.bank_type_id
            ).first()

            # create company banking info obj
            logger.info(f"[{_id}] create company banking info obj")
            company_banking_data = CompanyBankingInfo(
                company_id = company_data.company_id,
                bank_type_id = bank_type_data.bank_type_id,
                routing_number= req_body.routing_number,
                product_code= req_body.product_code,
                sort_code= req_body.sort_code,
                payee_beneficiary= req_body.payee_beneficiary,
                institution_code= req_body.institution_code,
                billing_account_number= req_body.billing_account_number,
                billing_bank_code= req_body.billing_bank_code,
                billing_account_name= req_body.billing_account_name,
            )

            # add comany banking info to db
            logger.info(f"[{_id}] add comany banking info to db")
            session.add(company_banking_data)
            
            # flush data
            logger.info(f"[{_id}] flush data")
            session.flush()


            if req_body.volume_tariff:
                # add volume tarrif data
                logger.info(f"[{_id}] add volume tarrif data")
                for vt in req_body.volume_tariff:
                    volume_tariff_data = VolumeTariff(
                        institution_id=None,
                        billing_id=billing_data.billing_id,
                        min_volume=vt.get("min_vol"),
                        max_volume=vt.get("max_vol"),
                        rate=vt.get("rate")
                    )
                    session.add(volume_tariff_data)

            # commit data
            logger.info(f"[{_id}] commit data")
            session.commit()

            if company_data:
                # format data
                logger.info(f"[{_id}] format data")
                company_data = Company_MF.model_validate(company_data).model_dump()  
                        
        # create response data
        logger.info(f"[{_id}] create response data")
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=True, message=None)
        _data = company_data
        _error = None
        _status_code = status.HTTP_200_OK
    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    

# # Update Company /company /company/billing /company/banking
@api.put("/company/{company_id}")
def update_company(
    *,
    company_id:str=Path(...),
    req_body:UpdateCompanyRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value:
        # create unathorized response data
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN
    else:

        # check if user has permission to use this endpoint
        logger.info(f"[{_id}] check if user has permission to use this endpoint")
        with database_client.Session() as session:

            # query company
            logger.info(f"[{_id}] query company")
            company_data = session.query(Company).filter(Company.public_id == company_id).first()

            # update company
            logger.info(f"[{_id}] update company")
            company_data.company_name = req_body.company_name
            company_data.client_id = req_body.client_id
            company_data.is_active = req_body.is_active
            company_data.auto_disable_days = req_body.auto_disable_days

            try:
                # flush data
                logger.info(f"[{_id}] flush data")
                session.flush()
            except sqlalchemy.exc.IntegrityError as e:
                # create company/client_id exists response data
                logger.info(f"[{_id}] create company/client_id exists response data")
                _response_message = "company/client_id exists"
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
                _data = None
                _error = BaseError(error_message=_response_message)
                _status_code = status.HTTP_400_BAD_REQUEST
    
                # create response
                logger.info(f"[{_id}] create response")
                _content = _response(meta=_meta, data=_data, error=_error)
                return ORJSONResponse(status_code=_status_code, content=_content.model_dump())


            # commit data
            logger.info(f"[{_id}] commit data")
            session.commit()
        
            if company_data:
                # format data
                logger.info(f"[{_id}] format data")
                company_data = Company_MF.model_validate(company_data).model_dump()  

        # create response data
        logger.info(f"[{_id}] create response data")
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=True, message=None)
        _data = company_data
        _error = None
        _status_code = status.HTTP_200_OK
    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    


@api.put("/company/{company_id}/billing")
def update_company_billing(
    *,
    company_id:str=Path(...),
    req_body:UpdateCompanyBillingRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value:
        # create unathorized response data
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN
    else:

        # check if user has permission to use this endpoint
        logger.info(f"[{_id}] check if user has permission to use this endpoint")
        with database_client.Session() as session:


            # query company and billing data
            logger.info(f"[{_id}] query company and billing data")
            company_data, billing_data = session.query(
                Company,
                BillingInformation
            ).join(
                Company,
                BillingInformation.company_id == Company.company_id
            ).filter(
                Company.public_id==company_id
            ).first()


            # query billing frequency data
            logger.info(f"[{_id}] query billing frequency data")
            billing_frequency_data = session.query(BillingFrequencyMaster).filter(BillingFrequencyMaster.public_id == req_body.billing_frequency_id).first()
            # query billing mode data
            logger.info(f"[{_id}] query billing mode data")
            billing_mode_type_data = session.query(BillingModeTypeMaster).filter(BillingModeTypeMaster.public_id==req_body.billing_mode_type_id).first()
            # query institution data
            logger.info(f"[{_id}] query institution data")
            institution_data = session.query(Institution).filter(Institution.public_id==req_body.institution_id).first()


            # update data
            logger.info(f"[{_id}] update data")
            billing_data.email_id1=req_body.email_id1
            billing_data.floor_cost=req_body.floor_cost
            billing_data.vat=req_body.vat 
            # currency_id:Optional[float]
            billing_data.billing_start_date=req_body.billing_start_date
            billing_data.billing_end_date=req_body.billing_end_date
            billing_data.billing_frequency_id=billing_frequency_data.billing_frequency_id
            billing_data.billing_mode_type_id=billing_mode_type_data.billing_mode_type_id
            billing_data.institution_id=institution_data.institution_id if institution_data else None


            # update volume tarrif
            logger.info(f"[{_id}] update volume tarrif")
            volume_tariff_data = session.query(
                VolumeTariff
            ).filter(
                VolumeTariff.billing_id == billing_data.billing_id
            ).all()

            if volume_tariff_data:
                for vt in volume_tariff_data:
                    session.delete(vt)
            
            if req_body.volume_tariff:
                for vt in req_body.volume_tariff:
                    volume_tariff_data = VolumeTariff(
                        institution_id=None,
                        billing_id=billing_data.billing_id,
                        min_volume=vt.get("min_vol"),
                        max_volume=vt.get("max_vol"),
                        rate=vt.get("rate")
                    )
                    session.add(volume_tariff_data)


            # flush data
            logger.info(f"[{_id}] flush data")
            session.flush()

            # commit data
            logger.info(f"[{_id}] commit data")
            session.commit()


            if company_data:

                # format company data
                logger.info(f"[{_id}] format company data")
                company_data = Company_MF.model_validate(company_data).model_dump()  
                        
            # create response data
            logger.info(f"[{_id}] create response data")
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=True, message=None)
            _data = company_data
            _error = None
            _status_code = status.HTTP_200_OK

    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    

@api.put("/company/{company_id}/banking")
def update_company_banking(
    *,
    company_id:str=Path(...),
    req_body:UpdateCompanyBankingRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):

    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value:
        # create unathorized response data
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN
    else:

        # check if user has permission to use this endpoint
        logger.info(f"[{_id}] check if user has permission to use this endpoint")
        with database_client.Session() as session:


            # query company and banking data
            logger.info(f"[{_id}] query company and banking data")
            company_data, banking_data = session.query(
                Company,
                CompanyBankingInfo
            ).join(
                CompanyBankingInfo,
                CompanyBankingInfo.company_id == Company.company_id
            ).filter(
                Company.public_id==company_id
            ).first()


            # query bank type data
            logger.info(f"[{_id}] query bank type data")
            bank_type_data = session.query(BankTypeMaster).filter(BankTypeMaster.public_id == req_body.bank_type_id).first()


            # update banking data
            logger.info(f"[{_id}] update banking data")
            banking_data.bank_type_id=bank_type_data.bank_type_id
            banking_data.routing_number=req_body.routing_number
            banking_data.product_code=req_body.product_code
            banking_data.sort_code=req_body.sort_code
            banking_data.payee_beneficiary=req_body.payee_beneficiary
            # banking_data.gateway_client_id=req_body.gateway_client_id
            banking_data.institution_code=req_body.institution_code
            banking_data.billing_account_number=req_body.billing_account_number
            banking_data.billing_bank_code=req_body.billing_bank_code
            banking_data.billing_account_name=req_body.billing_account_name


            # commit data
            logger.info(f"[{_id}] commit data")
            session.commit()
        
            if company_data:
                # format company data
                logger.info(f"[{_id}] format company data")
                company_data = Company_MF.model_validate(company_data).model_dump()  
                        

            # create response data
            logger.info(f"[{_id}] create response data")
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=True, message=None)
            _data = company_data
            _error = None
            _status_code = status.HTTP_200_OK

    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    
# Delete Company
@api.delete("/company/{company_id}")
def delete_company(
    *,

    company_id:str=Path(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value:
        # create unathorized response data
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN
    else:

        # check if user has permission to use this endpoint
        logger.info(f"[{_id}] check if user has permission to use this endpoint")
        with database_client.Session() as session:

            # create query
            logger.info(f"[{_id}] create query")
            company_data = session.query(
                Company
            ).filter(
                Company.public_id == company_id
            )
            # query db
            logger.info(f"[{_id}] query db")
            company_data = company_data.first()

            if not company_data:
                # create company not found response data
                logger.info(f"[{_id}] create company not found response data")
                _response_message = "company not found"
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
                _data = None
                _error = BaseError(error_message=_response_message)
                _status_code = status.HTTP_404_NOT_FOUND
            else:
                # query company banking data
                logger.info(f"[{_id}] query company banking data")
                company_banking_data = session.query(CompanyBankingInfo).filter(CompanyBankingInfo.company_id == company_data.company_id).first()
                if company_banking_data:
                    # delete company banking data
                    logger.info(f"[{_id}] delete company banking data")
                    session.delete(company_banking_data)

                # delete company
                logger.info(f"[{_id}] delete company")
                session.delete(company_data)
                # commit data
                logger.info(f"[{_id}] commit data")
                session.commit()


                # create response data
                logger.info(f"[{_id}] create response data")
                _response_message = "deleted"
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message=_response_message)
                _data = None
                _error = None
                _status_code = status.HTTP_200_OK
    
    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())


# Wallet
@api.get("/company/{company_id}/wallet")
def wallet(
    *,
    company_id:str=Path(...),

    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if not (role_id == PortalRole.SUPER_ADMIN.value or role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value): # SUPER ADMIN
        # create unathorized response data
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN
    else:

        # check if user has permission to use this endpoint
        logger.info(f"[{_id}] check if user has permission to use this endpoint")
        with database_client.Session() as session:
            
            # query wallet
            logger.info(f"[{_id}] query wallet")
            wallet_data = session.query(
                Wallet
            ).join(
                Company,
                Wallet.company_id == Company.company_id
            ).filter(
                Company.public_id==company_id
            ).first()

        if wallet_data:
            # format wallet data
            logger.info(f"[{_id}] format wallet data")
            wallet_data = wallet_data.to_dict()

            # create response data
            logger.info(f"[{_id}] create response data")
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=True, message=None)
            _data = wallet_data
            _error = None
            _status_code = status.HTTP_200_OK

        else:
            # create wallet not found response data
            logger.info(f"[{_id}] create wallet not found response data")
            _response_message = "wallet not found"
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
            _data = None
            _error = BaseError(error_message=_response_message)
            _status_code = status.HTTP_404_NOT_FOUND

    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())


@api.post("/company/{company_id}/wallet/load_wallet")
async def load_wallet(
    *,
    company_id:str=Path(...),
    # amount:int = Body(...),

    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")
    # get amount from body
    logger.info(f"[{_id}]  get amount from body")
    amount = (await request.json()).get('amount')

    # check if user has permission to use this endpoint
    logger.info(f"[{_id}] check if user has permission to use this endpoint")
    if role_id == PortalRole.EXPLORER.value: # SUPER ADMIN
        # create unathorized response data
        logger.info(f"[{_id}] create unathorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN
    else:

        # check if user has permission to use this endpoint
        logger.info(f"[{_id}] check if user has permission to use this endpoint")
        with database_client.Session() as session:
            
            # query wallet data
            logger.info(f"[{_id}] query wallet data")
            wallet_data = session.query(
                Wallet
            ).join(
                Company,
                Wallet.company_id == Company.company_id
            ).filter(
                Company.public_id==company_id
            ).first()

            if wallet_data:
                # updte wallet
                logger.info(f"[{_id}] updte wallet")
                wallet_data.amount += amount
                wallet_data.ledger_amount += amount
                session.flush()
                session.commit()

                # create response data
                logger.info(f"[{_id}] create response data")
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message=None)
                _data = wallet_data.to_dict()
                _error = None
                _status_code = status.HTTP_200_OK

            else:
                # create wallet not found response data
                logger.info(f"[{_id}] create wallet not found response data")
                _response_message = "wallet not found"
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
                _data = None
                _error = BaseError(error_message=_response_message)
                _status_code = status.HTTP_404_NOT_FOUND

    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())


# Institution
# GET Institutions
@api.get("/institutions")
def institutions(
    *,
    x_verbose:bool=Header(True, alias="x-verbose"),
    x_ignore_pagination:bool=Header(False, alias="x-ignore-pagination"),

    page_no:int= Query(1),
    items_per_page:int= Query(15),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # check if user has permission to use this api
    logger.info(f"[{_id}] check if user has permission to use this api")
    if role_id == PortalRole.SUPER_ADMIN.value:

        # create session with db
        logger.info(f"[{_id}] create session with db")
        with database_client.Session() as session:

            # setup non verbose data
            logger.info(f"[{_id}] create query")
            non_verbose_data = (Institution.public_id.label("institution_id"), Institution.institution_name)
            data_to_query = (Institution,) if x_verbose else non_verbose_data

            # basic query
            query = session.query( *data_to_query )

            
            # get total count for pagination
            logger.info(f"[{_id}] get total count for pagination")
            total_count = session.query(func.count()).select_from(Institution).scalar()

            # pagination
            if not x_ignore_pagination:
                logger.info(f"[{_id}] add pagination to query")
                offset = (page_no - 1) * items_per_page
                query = query.order_by(Institution.create_date).offset(offset).limit(items_per_page)

            # get all data
            logger.info(f"[{_id}] query db")
            institution_data = query.all()

            if institution_data:
                # format data
                logger.info(f"[{_id}] format data")
                institution_data = [  Institution_MF.model_validate(i).model_dump() if x_verbose else i._asdict() for i in institution_data  ]

        # create response data
        logger.info(f"[{_id}] create response data")
        _response = PaginationResponse
        _pagination_data = PaginationData(items_per_page=items_per_page, page_no=page_no, total_count=total_count, page_url=request.url._url )
        _meta = PaginationMeta(_id=_id, successful=True, message=None, pagination_data=_pagination_data)
        _data = institution_data
        _error = None
        _status_code = status.HTTP_200_OK

    else:
        # create unauthorized response data
        logger.info(f"[{_id}] create unauthorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN

    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    
# GET Institution
@api.get("/institution/{institution_id}")
def institution(
    *,
    institution_id:str= Path(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")


    # check if user has permission to use this api
    logger.info(f"[{_id}] check if user has permission to use this api")
    if role_id == PortalRole.SUPER_ADMIN.value:

        # create session with db
        logger.info(f"[{_id}] create session with db")
        with database_client.Session() as session:


            # basic query
            logger.info(f"[{_id}] create query")
            query = session.query( Institution ).options(joinedload(Institution.volume_tariff)).filter(Institution.public_id == institution_id )

            # get all data
            logger.info(f"[{_id}] query db")
            institution_data = query.first()
            
            if institution_data:
                # format data
                logger.info(f"[{_id}] format data")
                institution_data = Institution_MF.model_validate(institution_data).model_dump()
                # create response data
                logger.info(f"[{_id}] create response data")
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message=None)
                _data = institution_data
                _error = None
                _status_code = status.HTTP_200_OK
            else:
                # create institution not found response data
                logger.info(f"[{_id}] create institution not found response data")
                _response_message = "institution not found"
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
                _data = None
                _error = BaseError(error_message=_response_message)
                _status_code = status.HTTP_404_NOT_FOUND                

    else:
        # create unauthorized response data
        logger.info(f"[{_id}] create unauthorized response data")
        _response_message = "unauthorized"
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
        _data = None
        _error = BaseError(error_message=_response_message)
        _status_code = status.HTTP_403_FORBIDDEN

    # create  response 
    logger.info(f"[{_id}] create  response ")    
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    
# POST Institution

@api.post("/institution")
def create_institution(
    *,
    req_body:CreateInstitutionRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # create session with db
    logger.info(f"[{_id}] create session with db")
    with database_client.Session() as session:

        billing_frequency_data = session.query(
            BillingFrequencyMaster
        ).filter(
            BillingFrequencyMaster.public_id==req_body.billing_frequency_id
        ).first()

        billing_mode_type_data = session.query(
            BillingModeTypeMaster
        ).filter(
            BillingModeTypeMaster.public_id==req_body.billing_mode_type_id
        ).first()

        # check if user has permission to use this api
        logger.info(f"[{_id}] check if user has permission to use this api")
        if ( role_id not in (PortalRole.SUPER_ADMIN.value) ):

            # create unauthorized response data
            logger.info(f"[{_id}] create unauthorized response data")
            _response_message = "unauthorized"
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
            _data = None
            _error = BaseError(error_message=_response_message)
            _status_code = status.HTTP_403_FORBIDDEN

        else:
            # create institution object
            logger.info(f"[{_id}] create institution object")
            institution_data = Institution(
                institution_name=req_body.institution_name,
                floor_cost=req_body.floor_cost,
                vat=req_body.vat,
                currency_id=1,
                billing_start_date=req_body.billing_start_date,
                billing_end_date=req_body.billing_end_date,
                billing_frequency_id=billing_frequency_data.billing_frequency_id,
                billing_mode_type_id=billing_mode_type_data.billing_mode_type_id
            )

            try:
                # add institution to db
                logger.info(f"[{_id}] add institution to db")
                session.add(institution_data)
                # flush session
                logger.info(f"[{_id}] flush session")
                session.flush()

                # add volume tarrif to db
                logger.info(f"[{_id}] add volume tarrif to db")
                if req_body.volume_tariff:
                    for vt in req_body.volume_tariff:
                        volume_tariff_data = VolumeTariff(
                            institution_id=institution_data.institution_id,
                            billing_id=None,
                            min_volume=vt.get("min_vol"),
                            max_volume=vt.get("max_vol"),
                            rate=vt.get("rate")
                        )
                        session.add(volume_tariff_data)

                # commit changes to db
                logger.info(f"[{_id}] commit changes to db")
                session.commit()
                # refresh data
                logger.info(f"[{_id}] refresh data")
                session.refresh(institution_data)

                # format data
                logger.info(f"[{_id}] format data")
                institution_data = Institution_MF.model_validate(institution_data).model_dump()
                
                # create response data
                logger.info(f"[{_id}] create response data")
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message="created")
                _data = institution_data
                _error = None
                _status_code = status.HTTP_200_OK
            except sqlalchemy.exc.IntegrityError as e:

                # create user exists response data
                logger.info(f"[{_id}] create user exists response data")
                _response_message = "user exists"
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
                _data = None
                _error = BaseError(error_message=_response_message)
                _status_code = status.HTTP_400_BAD_REQUEST

    # create response 
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    
# PUT Institution
@api.put("/institution/{institution_id}")
def update_institution(
    *,
    institution_id: str = Path(...),
    req_body: UpdateInstitutionRequest = Body(...),
    decoded_token: dict = Depends(decodeJwtTokenDependancy),
    request:Request
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")


    # create session with db
    logger.info(f"[{_id}] create session with db")
    with database_client.Session() as session:

        # create unauthorized response data
        logger.info(f"[{_id}] create unauthorized response data")
        if role_id != PortalRole.SUPER_ADMIN.value:
            _response_message = "unauthorized"
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
            _data = None
            _error = BaseError(error_message=_response_message)
            _status_code = status.HTTP_403_FORBIDDEN
        else:
            # retrieve the institution to be updated
            logger.info(f"[{_id}] retrieve the institution to be updated")
            institution_data = session.query(Institution).filter(Institution.public_id == institution_id).first()
            billing_frequency_data = session.query(BillingFrequencyMaster).filter(BillingFrequencyMaster.public_id == req_body.billing_frequency_id).first()
            billing_mode_type_data = session.query(BillingModeTypeMaster).filter(BillingModeTypeMaster.public_id==req_body.billing_mode_type_id).first()

            if institution_data:
                # update institution data
                logger.info(f"[{_id}] update institution data")
                institution_data.institution_name = req_body.institution_name
                institution_data.floor_cost = req_body.floor_cost
                institution_data.vat = req_body.vat
                institution_data.billing_start_date = req_body.billing_start_date
                institution_data.billing_end_date = req_body.billing_end_date
                institution_data.billing_frequency_id=billing_frequency_data.billing_frequency_id
                institution_data.billing_mode_type_id=billing_mode_type_data.billing_mode_type_id
                
                #  get volume tarrif data
                logger.info(f"[{_id}] get volume tarrif data")
                volume_tariff_data = session.query(
                    VolumeTariff
                ).filter(
                    VolumeTariff.institution_id == institution_data.institution_id
                ).all()

                if volume_tariff_data:
                    #  delete volume tarrif data
                    logger.info(f"[{_id}] delete volume tarrif data")
                    for vt in volume_tariff_data:
                        session.delete(vt)
                
                if req_body.volume_tariff:
                    #  add volume tarrif data
                    logger.info(f"[{_id}] add volume tarrif data")
                    for vt in req_body.volume_tariff:
                        volume_tariff_data = VolumeTariff(
                            institution_id=institution_data.institution_id,
                            billing_id=None,
                            min_volume=vt.get("min_vol"),
                            max_volume=vt.get("max_vol"),
                            rate=vt.get("rate")
                        )
                        session.add(volume_tariff_data)

                #  flush + commit data
                logger.info(f"[{_id}] flush + commit data")
                session.flush()
                session.commit()

                #  format data
                logger.info(f"[{_id}] format data")
                institution_data = Institution_MF.model_validate(institution_data).model_dump()
                
                #  create response data
                logger.info(f"[{_id}] create response data")
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message="updated")
                _data = institution_data
                _error = None
                _status_code = status.HTTP_200_OK
            else:
                #  create institution not found data
                logger.info(f"[{_id}] create institution not found data")
                _response_message = "institution not found" 
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
                _data = None
                _error = BaseError(error_message=_response_message)
                _status_code = status.HTTP_404_NOT_FOUND
    
    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())

# Delete INSTITUTIon
@api.delete("/institution/{institution_id}")
def delete_institution(
    *,
    institution_id: str = Path(...),
    decoded_token: dict = Depends(decodeJwtTokenDependancy),
    request:Request
):
    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # create session with db
    logger.info(f"[{_id}] create session with db")
    with database_client.Session() as session:

        # check if user has permission
        logger.info(f"[{_id}] check if user has permission")
        if role_id != PortalRole.SUPER_ADMIN.value:
            # create unauthorized response data
            logger.info(f"[{_id}] create unauthorized response data")
            _response_message = "unauthorized"
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
            _data = None
            _error = BaseError(error_message=_response_message)
            _status_code = status.HTTP_403_FORBIDDEN
        else:
            # retrieve the institution to be deleted
            logger.info(f"[{_id}] retrieve the institution to be deleted")
            institution_data = session.query(Institution).filter(Institution.public_id == institution_id).first()

            if institution_data:
                # delete institution from the database
                logger.info(f"[{_id}] delete institution from the database")
                session.delete(institution_data)
                # commit data
                logger.info(f"[{_id}] commit data")
                session.commit()

                # create response data
                logger.info(f"[{_id}] create response data")
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message="deleted")
                _data = None
                _error = None
                _status_code = status.HTTP_200_OK
            else:
                #  create institution not found data
                logger.info(f"[{_id}] create institution not found data")
                _response_message = "institution not found" 
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
                _data = None
                _error = BaseError(error_message=_response_message)
                _status_code = status.HTTP_404_NOT_FOUND

    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())

# volume tarrif
@api.post("/volume_tariff")
def volume_tariff(
    *,
    x_id_type: str = Header("institution", alias="x-id-type"),
    req_body:AddVolumeTariffRequest=Body(...),
    decoded_token: dict = Depends(decodeJwtTokenDependancy),
    request:Request
):

    # create request id
    _id = request.state.session_code
    # get role id of logged in user
    logger.info(f"[{_id}] get role id from jwt token")
    role_id =  decoded_token.get("rid")

    # create session with db
    logger.info(f"[{_id}] create session with db")
    with database_client.Session() as session:

        # check if user has permission
        logger.info(f"[{_id}] check if user has permission")
        if role_id != PortalRole.SUPER_ADMIN.value:
            # create unauthorized response data
            logger.info(f"[{_id}] create unauthorized response data")
            _response_message = "unauthorized"
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
            _data = None
            _error = BaseError(error_message=_response_message)
            _status_code = status.HTTP_403_FORBIDDEN
        else:

            # filter billing information
            logger.info(f"[{_id}] filter billing information")
            if x_id_type == "company":
                _institution_id = None
                billing_data = session.query(BillingInformation).join(Company,Company.company_id==BillingInformation.company_id).filter(Company.public_id==req_body.item_id).first()
                _billing_id = billing_data.billing_id
            elif x_id_type == "institution":
                institution_data = session.query(Institution).filter(Institution.public_id==req_body.item_id).first()
                _billing_id = None
                _institution_id = institution_data.institution_id


            if _institution_id or _billing_id:
                # create volume tarrif obj
                logger.info(f"[{_id}] create volume tarrif obj")
                volume_tariff_data = VolumeTariff(
                    institution_id = _institution_id,
                    billing_id = _billing_id,
                    min_volume = req_body.min_vol,
                    max_volume = req_body.max_vol,
                    rate = req_body.rate
                )

                # add volume tarrif
                logger.info(f"[{_id}] add volume tarrif")
                session.add(volume_tariff_data)
                # commit volume tarrif
                logger.info(f"[{_id}] commit volume tarrif")
                session.commit()

                # create response data
                logger.info(f"[{_id}] create response data")
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message="created")
                _data = volume_tariff_data.to_dict()
                _error = None
                _status_code = status.HTTP_200_OK
            else:
                #  create institution/company not found data
                logger.info(f"[{_id}] create institution/company not found data")
                _response_message = "institution/company not found" 
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message=_response_message)
                _data = None
                _error = BaseError(error_message=_response_message)
                _status_code = status.HTTP_404_NOT_FOUND

    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())

