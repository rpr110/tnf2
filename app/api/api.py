#############
## Imports ##
#############

import io
import uuid
import csv
import datetime

import pandas as pd

import sqlalchemy
from sqlalchemy import func
from sqlalchemy.orm import selectinload, joinedload, aliased


from fastapi import APIRouter, Body, Depends, File, UploadFile, Form, Query, status, Request, Path, Header
from fastapi.responses import ORJSONResponse, StreamingResponse

from app.utils.dependencies import generateJwtToken, decodeJwtTokenDependancy
from app.utils.schema import *
from app import database_client, email_client, otp_client
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
def login(req_body:LoginRequest=Body(...)):
    
    # create request id
    _id = str(uuid.uuid4())

    # create session with db
    with database_client.Session() as session:

        # query the employee
        employee_data = session.query(
            Employee
        ).options(
            selectinload(Employee.role), selectinload(Employee.company)
        ).filter(
            Employee.email_id == req_body.email_id
        ).first()

        # check if employee exists / wrong password / is active (ie. is account disabled)
        if not employee_data or employee_data.password != req_body.password or not employee_data.is_active:

            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message="invalid credentials")
            _data = None
            _error = BaseError(error_message="invalid credentials")
            _status_code = status.HTTP_401_UNAUTHORIZED

        else:        

            # retrive all employee info and format the data
            employee_data = Employee_MF.model_validate(employee_data).model_dump()

            # create jwt token
            jwt_token = generateJwtToken(
                exp=100000,
                uid=employee_data.get("employee_id"), # User ID
                cid=employee_data.get("company",{}).get("company_id"), # Company ID
                rid=employee_data.get("role",{}).get("role_id"), # Role ID
                sid=_id
            )

            _response = TokenResponse
            _meta = TokenMeta(_id=_id, successful=True, message="logged in", token=jwt_token)
            # _data = employee_data
            _data = None
            _error = None
            _status_code = status.HTTP_200_OK


    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())


@api.post("/forgot_password")
def forgot_password(req_body:ForgotPasswordRequest=Body(...)):
    
    # Create request_id
    _id = str(uuid.uuid4())

    # create session with db
    with database_client.Session() as session:

        # query the employee
        employee_data = session.query(
            Employee
        ).filter(
            Employee.email_id == req_body.email_id
        ).first()

        # check if employee exists / is active
        if not employee_data or not employee_data.is_active:
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message="invalid credentials")
            _data = None
            _error = BaseError(error_message="invalid credentials")
            _status_code = status.HTTP_401_UNAUTHORIZED
        else:
            # Create Verification code
            verification_code = otp_client.create_verification_code(6)

            # Create Verification code Session in DB
            otp_client.create_verification_code_session(session, VerificationCode, req_body.email_id, verification_code)
            
            # Send EMAIL
            email_client.send_mail(req_body.email_id, "Verification Code", f"Your Verification Code: {verification_code}")

            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=True, message="verification code sent")
            _data = None
            _error = None
            _status_code = status.HTTP_200_OK


    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    
@api.post("/reset_password")
def reset_password(req_body:ResetPasswordRequest = Body(...)):
    
    # create request id
    _id = str(uuid.uuid4())

    # create session with db
    with database_client.Session() as session:

        # query verification code
        verification_code_data = session.query(
            VerificationCode
        ).filter(
            VerificationCode.email_id == req_body.email_id
        ).first()

        # check if verification code is valid
        # verification_code_is_expired = ( datetime.datetime.now(pytz.utc) - verification_code_data.create_date.astimezone(pytz.utc) > datetime.timedelta(minutes=5) )
        verification_code_is_expired = False
        if not verification_code_data or verification_code_is_expired or verification_code_data._code != req_body.code:

            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message="invalid credentials")
            _data = None
            _error = BaseError(error_message="invalid credentials")
            _status_code = status.HTTP_401_UNAUTHORIZED

        else:

            # update password
            employee_data = session.query(
                Employee
            ).filter(
                Employee.email_id  == req_body.email_id
            ).first()

            employee_data.password = req_body.new_password

            session.commit()

            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=True, message=f"password updated for {req_body.email_id}")
            _data = None
            _error = None
            _status_code = status.HTTP_200_OK

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
):
    
    # create request id
    _id = str(uuid.uuid4())
    # get role of logged in user
    role_id = decoded_token.get("rid")

    # create session with db
    with database_client.Session() as session:

        non_verbose_data = (Roles.role_name, Roles.public_id.label("role_id"))
        data_to_query = (Roles,) if x_verbose else non_verbose_data

        role_data = session.query(*data_to_query)
        role_data = role_data.all() if role_id == PortalRole.SUPER_ADMIN.value else role_data.filter(Roles.public_id != PortalRole.SUPER_ADMIN.value).all()

        role_data = [ Roles_MF.model_validate(i).model_dump() if x_verbose else i._asdict() for i in role_data ] 
        
    _response = BaseResponse
    _meta = BaseMeta(_id=_id, successful=True, message="retrieved roles")
    _data = role_data
    _error = None
    _status_code = status.HTTP_200_OK

    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    
    
@api.get("/employees")
def get_all_employees(
    *,
    x_verbose:bool=Header(True, alias="x-verbose"),
    company_id:str=Query(...),
    page_no:int= Query(1),
    items_per_page:int= Query(15),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    # create request id
    _id = str(uuid.uuid4())
    # get role id of logged in user
    role_id =  decoded_token.get("rid")


    # check if non super admin + company_id == all or company_id != cid
    if not (role_id != PortalRole.SUPER_ADMIN.value and (company_id != decoded_token.get("cid"))) and role_id in (_.value for _ in PortalRole)  :

        # create session with db
        with database_client.Session() as session:

            # setup non verbose data
            non_verbose_data = (Employee.public_id.label("employee_id"), Employee.email_id, Employee.employee_name, Employee.phone_number)
            data_to_query = (Employee,) if x_verbose else non_verbose_data
            query_options = (joinedload(Employee.role), joinedload(Employee.company), ) if x_verbose else ()

            # basic query
            query = session.query( *data_to_query ).options( *query_options )

            if company_id != "all": 
                # filter by company id
                query = query.join(
                    Company,
                    Company.company_id == Employee.company_id
                ).filter(
                    Company.public_id == company_id
                )
            
            # get total count for pagination
            total_count = session.query(func.count()).select_from(Employee).scalar()

            # pagination
            offset = (page_no - 1) * items_per_page
            query = query.order_by(Employee.create_date).offset(offset).limit(items_per_page)

            # get all data
            employee_data = query.all()

            if employee_data:
                # format data
                employee_data = [  Employee_MF.model_validate(i).model_dump() if x_verbose else i._asdict() for i in employee_data  ]
        
        _response = PaginationResponse
        _pagination_data = PaginationData(items_per_page=items_per_page, page_no=page_no, total_count=total_count, page_url=request.url._url )
        _meta = PaginationMeta(_id=_id, successful=True, message=None, pagination_data=_pagination_data)
        _data = employee_data
        _error = None
        _status_code = status.HTTP_200_OK

    else:

        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message="unauthorized")
        _data = None
        _error = BaseError(error_message="unauthorized")
        _status_code = status.HTTP_403_FORBIDDEN

    
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    

@api.get("/employee/{employee_id}")
def get_employee(
    *,
    x_verbose:bool=Header(True, alias="x-verbose"),
    employee_id:str=Path(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
    
    # create request id
    _id = str(uuid.uuid4())
    # get role id of logged in user
    role_id =  decoded_token.get("rid")

    if  role_id not in (_.value for _ in PortalRole)  :
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message="unauthorized")
        _data = None
        _error = BaseError(error_message="unauthorized")
        _status_code = status.HTTP_403_FORBIDDEN

    else:

        # create session with db
        with database_client.Session() as session:

            non_verbose_data = (Employee.public_id.label("employee_id"), Employee.email_id, Employee.employee_name, Employee.phone_number)
            data_to_query = (Employee,) if x_verbose else non_verbose_data
            query_options = (joinedload(Employee.role), joinedload(Employee.company), ) if x_verbose else ()

            query = session.query(
                *data_to_query
            ).options(
                *query_options
            )

            if role_id == PortalRole.SUPER_ADMIN.value:
                
                query = query.filter(
                    Employee.public_id == employee_id
                )

            elif role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value:
                
                query = query.join(
                    Company,
                    Company.company_id == Employee.company_id
                ).filter(
                    Employee.public_id == employee_id,
                    Company.public_id == decoded_token.get("cid")
                )

            employee_data = query.first()

            if employee_data:
                employee_data = Employee_MF.model_validate(employee_data).model_dump() if x_verbose else employee_data._asdict()

                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message=None)
                _data = employee_data
                _error = None
                _status_code = status.HTTP_200_OK

            else:
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message="user not found")
                _data = None
                _error = BaseError(error_message="user not found")
                _status_code = status.HTTP_404_NOT_FOUND


    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    

@api.post("/employee")
def create_employee(
    *,
    req_body:CreateEmployeeRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
    # create request id
    _id = str(uuid.uuid4())
    # get role id of logged in user
    role_id =  decoded_token.get("rid")

    # create session with db
    with database_client.Session() as session:
        # query company
        company_data = session.query(Company).filter(Company.public_id==req_body.company_id).first()
        # query role
        role_data = session.query(Roles).filter(Roles.public_id==req_body.role_id).first()
        
        # cheeck if role is valid or admin using differnt cid
        if ( role_id not in (PortalRole.SUPER_ADMIN.value, PortalRole.ADMIN.value) ) or (role_id == PortalRole.ADMIN.value and decoded_token.get("cid") != company_data.public_id):
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message="unauthorized")
            _data = None
            _error = BaseError(error_message="unauthorized")
            _status_code = status.HTTP_403_FORBIDDEN

        else:
            # create employee object
            employee_data = Employee(
                email_id=req_body.email_id,
                password=req_body.password,
                employee_name=req_body.employee_name,
                phone_number=req_body.phone_number,
                employee_profile_pic=req_body.employee_profile_pic,
                company_id=company_data.company_id,
                role_id=role_data.role_id
            )

            try:
                # add employee to db
                session.add(employee_data)
                session.commit()
                session.refresh(employee_data)
                
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message="created")
                _data = Employee_MF.model_validate(employee_data).model_dump()
                _error = None
                _status_code = status.HTTP_200_OK
            except sqlalchemy.exc.IntegrityError as e:

                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message="user exists")
                _data = None
                _error = BaseError(error_message="user exists")
                _status_code = status.HTTP_400_BAD_REQUEST


    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    

@api.put("/employee/{employee_id}")
def modify_employee(
    *,
    employee_id:str=Path(...),
    req_body:ModifyEmployeeDataRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
    # create request id
    _id = str(uuid.uuid4())
    # get role id of logged in user
    role_id =  decoded_token.get("rid")

    if  role_id not in (_.value for _ in PortalRole) or  (role_id == PortalRole.EXPLORER.value and employee_id != decoded_token.get("uid")):
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message="unauthorized")
        _data = None
        _error = BaseError(error_message="unauthorized")
        _status_code = status.HTTP_403_FORBIDDEN

    else:
        # create session with db
        with database_client.Session() as session:

            query = session.query(
                Employee
            )
            
            if role_id == PortalRole.SUPER_ADMIN.value or role_id == PortalRole.EXPLORER.value:
                employee_data = query.filter(
                    Employee.public_id == employee_id
                )

            elif role_id == PortalRole.ADMIN.value:
                employee_data = query.join(
                    Company,
                    Employee.company_id == Company.company_id
                ).filter(
                    Employee.public_id == employee_id,
                    Company.public_id == decoded_token.get("cid")
                )


            employee_data = employee_data.first()

            if not employee_data:
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message="user not found")
                _data = None
                _error = BaseError(error_message="user not found")
                _status_code = status.HTTP_404_NOT_FOUND
            else:
                employee_data.employee_name = req_body.employee_name
                employee_data.phone_number = req_body.phone_number
                employee_data.employee_profile_pic = req_body.employee_profile_pic

                session.commit()
                session.refresh(employee_data)

                employee_data = Employee_MF.model_validate(employee_data).model_dump()

                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message="updated")
                _data = employee_data
                _error = None
                _status_code = status.HTTP_200_OK

        
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    

@api.put("/employee/{employee_id}/update_password")
def update_password(
    *,
    employee_id:str=Path(...),
    req_body:ModifyEmployeePasswordRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
     # create request id
    _id = str(uuid.uuid4())
    # get role id of logged in user
    role_id =  decoded_token.get("rid")

    if  role_id not in (_.value for _ in PortalRole) or  (role_id == PortalRole.EXPLORER.value and employee_id != decoded_token.get("uid")):
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message="unauthorized")
        _data = None
        _error = BaseError(error_message="unauthorized")
        _status_code = status.HTTP_403_FORBIDDEN

    else:
        # create session with db
        with database_client.Session() as session:

            query = session.query(
                Employee
            )
            
            if role_id == PortalRole.SUPER_ADMIN.value or role_id == PortalRole.EXPLORER.value:
                query = query.filter(
                    Employee.public_id == employee_id
                )

            elif role_id == PortalRole.ADMIN.value:
                query = query.join(
                    Company,
                    Employee.company_id == Company.company_id
                ).filter(
                    Employee.public_id == employee_id,
                    Company.public_id == decoded_token.get("cid")
                )


            employee_data = query.first()

            if not employee_data:
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message="user not found")
                _data = None
                _error = BaseError(error_message="user not found")
                _status_code = status.HTTP_404_NOT_FOUND
            else:

                if role_id == PortalRole.EXPLORER.value and req_body.old_password != employee_data.password:
                    _response = BaseResponse
                    _meta = BaseMeta(_id=_id, successful=False, message="invalid credentials")
                    _data = None
                    _error = BaseError(error_message="invalid credentials")
                    _status_code = status.HTTP_403_FORBIDDEN
                else:
                    employee_data.password = req_body.new_password
                    _response = BaseResponse
                    _meta = BaseMeta(_id=_id, successful=True, message="updated")
                    _data = None
                    _error = None
                    _status_code = status.HTTP_200_OK

                    session.commit()

    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    
@api.delete("/employee/{employee_id}")
def delete_employee(
    *,
    employee_id:str=Path(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
     # create request id
    _id = str(uuid.uuid4())
    # get role id of logged in user
    role_id =  decoded_token.get("rid")

    if  role_id not in (PortalRole.SUPER_ADMIN.value, PortalRole.ADMIN.value) :
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message="unauthorized")
        _data = None
        _error = BaseError(error_message="unauthorized")
        _status_code = status.HTTP_403_FORBIDDEN

    else:
        # create session with db
        with database_client.Session() as session:

            query = session.query(
                Employee
            )
            
            if role_id == PortalRole.SUPER_ADMIN.value:
                query = query.filter(
                    Employee.public_id == employee_id
                )

            elif role_id == PortalRole.ADMIN.value:
                query = query.join(
                    Company,
                    Employee.company_id == Company.company_id
                ).filter(
                    Employee.public_id == employee_id,
                    Company.public_id == decoded_token.get("cid")
                )


            employee_data = query.first()

            if not employee_data:
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message="user not found")
                _data = None
                _error = BaseError(error_message="user not found")
                _status_code = status.HTTP_404_NOT_FOUND
            else:
                session.delete(employee_data)
                session.commit()
                
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message="deleted")
                _data = None
                _error = None
                _status_code = status.HTTP_200_OK


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
    x_response_type:str=Header("json",alias="x-response-type"), # json/ csv/ excel

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
    _id = str(uuid.uuid4())
    # get role id of logged in user
    role_id =  decoded_token.get("rid")


    if  role_id not in (_.value for _ in PortalRole) or  ( (role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value) and (company_id != decoded_token.get("cid") or company_id=="all") ):
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message="unauthorized")
        _data = None
        _error = BaseError(error_message="unauthorized")
        _status_code = status.HTTP_403_FORBIDDEN

    else:

        with database_client.Session() as session:
            
            query = session.query(
                NFaceLogs
            )

            if company_id != "all":

                query = query.join(
                    Company,
                    Company.company_id == NFaceLogs.company_id
                ).filter(
                    Company.public_id == company_id
                )
            

            if status_filter != "all":
                query = query.join(
                    StatusMaster,
                    StatusMaster.status_id == NFaceLogs.status_id
                ).filter(StatusMaster.status == status_filter.upper().strip())


            if service_filter != "all":
                query = query.join(
                    ServiceMaster,
                    ServiceMaster.service_id == NFaceLogs.service_id
                ).filter(ServiceMaster.service_name == service_filter.upper().strip())


            query = query.filter(NFaceLogs.create_date >= start_datetime,
                                    NFaceLogs.create_date <= end_datetime)
            
            
            # total_count = log_data.with_entities(func.count()).scalar()
            total_count = session.query(func.count()).select_from(NFaceLogs).scalar()


            # Pagination
            if not x_ignore_pagination:
                offset = (page_no - 1) * items_per_page
                query = query.order_by(NFaceLogs.create_date).offset(offset).limit(items_per_page)

            log_data = query.all()
            log_data = [ NFaceLogs_MF.model_validate(_).model_dump() for _ in log_data ]

            _response = PaginationResponse
            _pagination_data = PaginationData(items_per_page=items_per_page, page_no=page_no, total_count=total_count, page_url=request.url._url )
            _meta = PaginationMeta(_id=_id, successful=True, message=None, pagination_data=_pagination_data)
            _data = log_data
            _error = None
            _status_code = status.HTTP_200_OK

    if x_response_type == "json":

        _content = _response(meta=_meta, data=_data, error=_error)
        return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
        
    elif x_response_type == "csv":
        

        csv_data = io.StringIO()
        csv_writer = csv.DictWriter(csv_data, fieldnames=log_data[0].keys())
        csv_writer.writeheader()
        csv_writer.writerows(log_data)

        # Create a streaming response
        response = StreamingResponse(iter([csv_data.getvalue()]), media_type="text/csv")
        response.headers["Content-Disposition"] = "attachment;filename=output.csv"
        return response

# Stats
@api.get("/nface_logs/stats")
def get_nface_stats(
    *,
    company_id:str=Query(...), # all / company_id
    start_datetime:datetime.datetime = Query(...),
    end_datetime:datetime.datetime = Query(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
    # create request id
    _id = str(uuid.uuid4())
    # get role id of logged in user
    role_id =  decoded_token.get("rid")

    if  role_id not in (_.value for _ in PortalRole) or  ( (role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value) and (company_id != decoded_token.get("cid") or company_id=="all") ):
        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message="unauthorized")
        _data = None
        _error = BaseError(error_message="unauthorized")
        _status_code = status.HTTP_403_FORBIDDEN
    else:

        with database_client.Session() as session:
            
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
                query = query.join(
                    Company,
                    Company.company_id == NFaceLogs.company_id
                ).filter(
                    Company.public_id == company_id
                )


            query = query.filter(
                NFaceLogs.create_date >= start_datetime,
                NFaceLogs.create_date <= end_datetime
            )

            # Add grouping and ordering
            query = query.group_by(ServiceMaster.service_name, StatusMaster.status,)


            stat_dict = lambda x : {"FAILURE":x.get("FAILURE",0),"SUCCESS":x.get("SUCCESS",0),"ISSUE":x.get("ISSUE",0)}
            if query:
                query = query.all()
                nested_dict = {}
                for outer_key, inner_key, value in query:
                    if outer_key not in nested_dict:
                        nested_dict[outer_key] = {}
                    nested_dict[outer_key][inner_key] = value

            for k,v in nested_dict.items():
                nested_dict[k] = stat_dict(v)


            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=True, message=None)
            _data = nested_dict
            _error = None
            _status_code = status.HTTP_200_OK

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
    _id = str(uuid.uuid4())
    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:
        
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

        if bank_type_filter != "all":
            query = query.filter(BankTypeMaster.bank_type == bank_type_filter.upper().strip())

        if role_id == PortalRole.SUPER_ADMIN.value:
            if company_id != "all":
                query = query.join(Company, Company.company_id == Invoice.company_id).filter(Company.public_id == company_id)

        elif role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value:
            if company_id != decoded_token.get("cid") or company_id == "all":
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
            
            query = query.join(Company, Company.company_id == Invoice.company_id).filter(Company.public_id == company_id)

        
        if status_filter != "all":
            sf = 1 if status_filter.upper().strip() == "PAID" else 0
            query = query.filter(Invoice.payment_status == sf)
        
 
        query = query.filter(Invoice.end_date >= start_datetime,
                                Invoice.end_date <= end_datetime)

        if not x_ignore_pagination:
            offset = (page_no - 1) * items_per_page
            query = query.order_by(Invoice.end_date).offset(offset).limit(items_per_page)

        query = query.all()
        if query:
            query = [ {**q[0].to_dict(), "bank_type":q[-1]} for q in query ]

    exclude_data_keys = ("invoice_id","company_id","company.company_id","company.billing_id","company.billing_information")
    for i in range(len(query)):
        remove_keys_from_dict(query[i], exclude_data_keys)



    if x_response_type == "json":

        _content = BaseResponse(
            meta=BaseMeta(
                _id=_id,
                successful=True,
                message=None
            ),
            data=query,
            error=None
        )
        return ORJSONResponse(status_code=status.HTTP_200_OK, content=_content.model_dump())
        
    elif x_response_type == "csv":
        
        # Extract all billing dates from the query
        billing_dates = [row.get("end_date") for row in query if row.get("end_date")]

        # Find the maximum billing date
        max_billing_date = max(billing_dates) if billing_dates else None

        # Define the TXT file name with the formatted date
        if max_billing_date:
            formatted_date = datetime.datetime.strptime(max_billing_date, "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d")
            txt_file_name = f"N-Face_Billing_Smartdet_{formatted_date}.txt"
        else:
            txt_file_name = "N-Face_Billing_Smartdet.txt"

        max_billing_date = max(billing_dates) if billing_dates else None

        if bank_type_filter.lower().strip() == "all":
            dmb_columns = ["Routing_Number","product_code","Billing_date","Amount"]
            non_dmb_columns = ["Serial_No","Account_Number","Sort_Code","Payee_Beneficiary", "Amount", "Narration", "Payer", "Debit_Sort_Code", "Merchant_ID",  "CRDR", "Currency", "Cust_Code", "Beneficiary_BVN", "Payer_BVN", "Billing_Date"]

            dmb_data = []
            non_dmb_data = []
            for idx, row in enumerate(query):
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

            dmb_df = pd.DataFrame(dmb_data, columns=dmb_columns)
            non_dmb_df = pd.DataFrame(non_dmb_data, columns=non_dmb_columns)
            # Write both DataFrames to an Excel file with separate sheets
            excel_file_name = "output.xlsx"
            with pd.ExcelWriter(excel_file_name, engine='xlsxwriter') as writer:
                dmb_df.to_excel(writer, sheet_name='DMB', index=False)
                non_dmb_df.to_excel(writer, sheet_name='NON-DMB', index=False)

            # Open the file in binary mode for streaming
            excel_file_content_all = open(excel_file_name, "rb")

            # Create a streaming response for the Excel file
            response_all = StreamingResponse(iter([excel_file_content_all.read()]),
                                            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            response_all.headers["Content-Disposition"] = f"attachment;filename={excel_file_name}"

            # Optionally, close the file to free up resources
            excel_file_content_all.close()

            # Return the streaming response for "all"
            return response_all

        elif bank_type_filter.lower().strip() == "dmb":

            columns = ["Routing_Number","product_code","Billing_date","Amount"]
            
            txt_data = io.StringIO()
            txt_data.write('\t'.join(columns) + '\n')

            for row in query:
                routing_number = row.get("company",{}).get("banking_information",{}).get("routing_number",None)
                product_code = row.get("company",{}).get("banking_information",{}).get("product_code",None)
                billing_date = row.get("end_date",None)
                amount = float(row.get("amount",0))

                # Convert the date to the desired format ("yyyymmdd")
                formatted_billing_date = datetime.datetime.strptime(billing_date, "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d")

                # Write the data to the StringIO object with tab-separated values
                txt_data.write(f"{routing_number}\t{product_code}\t{formatted_billing_date}\t{amount}\n")

            # Reset the pointer to the beginning of the StringIO object
            txt_data.seek(0)

            # Create a streaming response for the TXT file
            response = StreamingResponse(iter([txt_data.getvalue()]), media_type="text/plain")
            response.headers["Content-Disposition"] = f"attachment;filename={txt_file_name}"

            # Optionally, close the StringIO object to free up resources
            txt_data.close()

            # Return the streaming response
            return response


        elif bank_type_filter.lower().strip() == "non-dmb":
            
            columns = ["Serial_No","Account_Number","Sort_Code","Payee_Beneficiary", "Amount", "Narration", "Payer", "Debit_Sort_Code", "Merchant_ID",  "CRDR", "Currency", "Cust_Code", "Beneficiary_BVN", "Payer_BVN", "Billing_Date"]

            # Initialize a list to store rows
            data = []

            # Populate the data list with rows
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
            df = pd.DataFrame(data, columns=columns)

            # Specify the Excel file name
            excel_file_name = "output.xlsx"

            # Write the DataFrame to an Excel file
            df.to_excel(excel_file_name, index=False)

            # Open the file in binary mode for streaming
            excel_file_content = open(excel_file_name, "rb")

            # Create a streaming response for the Excel file
            response = StreamingResponse(iter([excel_file_content.read()]), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            response.headers["Content-Disposition"] = f"attachment;filename={excel_file_name}"

            # Optionally, close the file to free up resources
            excel_file_content.close()

            # Return the streaming response
            return response
            

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
    
    _id = str(uuid.uuid4())
    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:


        # Perform the query using SQLAlchemy
        query = session.query(
            Invoice.payment_status,
            func.count(Invoice.payment_status).label('count'),
            func.sum(Invoice.amount).label('total_amount')
        )


        if role_id == PortalRole.SUPER_ADMIN.value:
            if company_id != "all":
                query = query.join(Company, Company.company_id == Invoice.company_id).filter(Company.public_id == company_id)

        elif role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value:
            if company_id != decoded_token.get("cid") or company_id == "all":
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
            
            query = query.join(Company, Company.company_id == Invoice.company_id).filter(Company.public_id == company_id)


        query = query.filter(NFaceLogs.create_date >= start_datetime,
                                NFaceLogs.create_date <= end_datetime)

        query = query.group_by(Invoice.payment_status)

        query = query.all()
        if query:
            nested_dict = {}
            for _status, _count, _amount in query:
                _status_name = "PAID" if _status == 1 else "PENDING"
                nested_dict[_status_name] = {}
                nested_dict[_status_name]["total_count"] = _count
                nested_dict[_status_name]["total_amount"] = _amount

    _content = BaseResponse(
        meta=BaseMeta(
            _id=_id,
            successful=True,
            message=None
        ),
        data=nested_dict,
        error=None
    )
    return ORJSONResponse(status_code=status.HTTP_200_OK, content=_content.model_dump())


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
    _id = str(uuid.uuid4())
    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:

        non_verbose_data = (BankTypeMaster.public_id, BankTypeMaster.bank_type,)
        data_to_query = (BankTypeMaster,) if x_verbose else non_verbose_data

        bank_type_data = session.query(
            *data_to_query
        )

        if role_id == PortalRole.SUPER_ADMIN.value: # SUPER ADMIN
            ...
        elif role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value: 
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
        

        if bank_type_data:
            bank_type_data = bank_type_data.all()
            dictify = lambda data,is_verbose : [i.to_dict() for i in data] if is_verbose else [i._asdict() for i in data]
            bank_type_data = dictify(bank_type_data, x_verbose)

            if x_verbose:
                exclude_data_keys = ("bank_type_id",)
                for i in range(len(bank_type_data)):
                    remove_keys_from_dict(bank_type_data[i],exclude_data_keys)

            _successful, _message, _data, _error, _status_code = True, None, bank_type_data, None, status.HTTP_200_OK
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


@api.get("/billing_frequency")
def billing_frequency(
    *,
    x_verbose:bool=Header(True, alias="x-verbose"),

    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    _id = str(uuid.uuid4())
    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:

        non_verbose_data = (BillingFrequencyMaster.public_id, BillingFrequencyMaster.billing_frequency,)
        data_to_query = (BillingFrequencyMaster,) if x_verbose else non_verbose_data

        billing_frequency_data = session.query(
            *data_to_query
        )

        if role_id == PortalRole.SUPER_ADMIN.value: # SUPER ADMIN
            ...
        elif role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value: 
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
        

        if billing_frequency_data:
            billing_frequency_data = billing_frequency_data.all()
            dictify = lambda data,is_verbose : [i.to_dict() for i in data] if is_verbose else [i._asdict() for i in data]
            billing_frequency_data = dictify(billing_frequency_data, x_verbose)

            if x_verbose:
                exclude_data_keys = ("billing_frequency_id",)
                for i in range(len(billing_frequency_data)):
                    remove_keys_from_dict(billing_frequency_data[i],exclude_data_keys)

            _successful, _message, _data, _error, _status_code = True, None, billing_frequency_data, None, status.HTTP_200_OK
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

@api.get("/billing_mode_type")
def billing_mode_type(
    *,
    x_verbose:bool=Header(True, alias="x-verbose"),

    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    _id = str(uuid.uuid4())
    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:

        non_verbose_data = (BillingModeTypeMaster.public_id, BillingModeTypeMaster.billing_mode_type,)
        data_to_query = (BillingModeTypeMaster,) if x_verbose else non_verbose_data

        billing_mode_data = session.query(
            *data_to_query
        )

        if role_id == PortalRole.SUPER_ADMIN.value: # SUPER ADMIN
            ...
        elif role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value: 
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
        

        if billing_mode_data:
            billing_mode_data = billing_mode_data.all()
            dictify = lambda data,is_verbose : [i.to_dict() for i in data] if is_verbose else [i._asdict() for i in data]
            billing_mode_data = dictify(billing_mode_data, x_verbose)

            if x_verbose:
                exclude_data_keys = ("billing_frequency_id",)
                for i in range(len(billing_mode_data)):
                    remove_keys_from_dict(billing_mode_data[i],exclude_data_keys)

            _successful, _message, _data, _error, _status_code = True, None, billing_mode_data, None, status.HTTP_200_OK
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
    _id = str(uuid.uuid4())

    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:

        non_verbose_data = (Company.public_id, Company.company_name,)
        data_to_query = (Company,) if x_verbose else non_verbose_data

        company_data = session.query(
            *data_to_query
        )
        if role_id == PortalRole.SUPER_ADMIN.value: # SUPER ADMIN
            ...
        elif role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value: 
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
        

        total_count = company_data.with_entities(func.count()).scalar()
        
        # Pagination
        if not x_ignore_pagination:
            offset = (page_no - 1) * items_per_page
            company_data = company_data.order_by(Company.create_date).offset(offset).limit(items_per_page)

        if company_data:
            company_data = company_data.all()
            dictify = lambda data,is_verbose : [Company_MF.model_validate(i).model_dump() for i in data] if is_verbose else [i._asdict() for i in data]
            company_data = dictify(company_data, x_verbose)

            # if x_verbose:
                # exclude_data_keys = ("company_id", "company.billing_id","company.billing_information.billing_frequency_id","company.billing_information.billing_id","company.billing_information.currency_id","company.billing_information.currency.currency_id","company.billing_information.billing_frequency.billing_frequency_id","company.banking_info.company_id","company.banking_info.bank_type_id","company.banking_info.bank_type.bank_type_id")
                # for i in range(len(company_data)):
                #     remove_keys_from_dict(company_data[i],exclude_data_keys)
                # for idx, _ in enumerate(company_data):

                #     if company_data[idx].get("billing_information",{}).get("volume_tariff"):
                #         company_data[idx]["billing_information"]["volume_tariff"] = [ VolumeTariff_MF.model_validate(i).model_dump() for i in company_data[idx]["billing_information"]["volume_tariff"] ] 
                #     if company_data[idx].get("billing_information",{}).get("institution",{}) and company_data[idx].get("billing_information",{}).get("institution",{}).get("volume_tariff") :
                #         company_data[idx]["billing_information"]["institution"]["volume_tariff"] = [ VolumeTariff_MF.model_validate(i).model_dump() for i in company_data[idx]["billing_information"]["institution"]["volume_tariff"] ] 
    
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
        data=company_data,
        error=None
    )

    return ORJSONResponse(status_code=status.HTTP_200_OK, content=_content.model_dump())

@api.get("/company/{company_id}")
def get_company(
    *,
    x_verbose:bool=Header(True, alias="x-verbose"),

    company_id:str=Path(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    _id = str(uuid.uuid4())

    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:

        non_verbose_data = (Company.public_id, Company.company_name,)
        data_to_query = (Company,) if x_verbose else non_verbose_data

        company_data = session.query(
            *data_to_query
        ).filter(
            Company.public_id==company_id
        )
        if role_id == PortalRole.SUPER_ADMIN.value: # SUPER ADMIN
            ...
        elif role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value: 
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
        

        if company_data:
            company_data = company_data.all()
            dictify = lambda data,is_verbose : [Company_MF.model_validate(i).model_dump() for i in data] if is_verbose else [i._asdict() for i in data]
            company_data = dictify(company_data, x_verbose)

            # if x_verbose:
            #     # exclude_data_keys = ("company_id", "company.billing_id","company.billing_information.billing_frequency_id","company.billing_information.billing_id","company.billing_information.currency_id","company.billing_information.currency.currency_id","company.billing_information.billing_frequency.billing_frequency_id","company.banking_info.company_id","company.banking_info.bank_type_id","company.banking_info.bank_type.bank_type_id")
            #     # for i in range(len(company_data)):
            #     #     remove_keys_from_dict(company_data[i],exclude_data_keys)
            #     for idx, _ in enumerate(company_data):

            #         if company_data[idx].get("billing_information",{}).get("volume_tariff"):
            #             company_data[idx]["billing_information"]["volume_tariff"] = [ VolumeTariff_MF.model_validate(i).model_dump() for i in company_data[idx]["billing_information"]["volume_tariff"] ] 
            #         if company_data[idx].get("billing_information",{}).get("institution",{}) and company_data[idx].get("billing_information",{}).get("institution",{}).get("volume_tariff") :
            #             company_data[idx]["billing_information"]["institution"]["volume_tariff"] = [ VolumeTariff_MF.model_validate(i).model_dump() for i in company_data[idx]["billing_information"]["institution"]["volume_tariff"] ] 
    
            _successful, _message, _data, _error, _status_code = True, None, company_data, None, status.HTTP_200_OK
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

# Onboard Client
@api.post("/register_client")
def onboard_client(
    *,
    req_body:RegisterClientRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    _id = str(uuid.uuid4())

    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:

        if role_id == PortalRole.SUPER_ADMIN.value:

            company_data = Company(
                company_name=req_body.company_name,
                is_active=True,
                client_id=req_body.client_id
            )

            session.add(company_data)

            try:
                session.flush()
            except sqlalchemy.exc.IntegrityError as e:
                _content = BaseResponse(
                    meta=BaseMeta(
                        _id=_id,
                        successful=False,
                        message="company/client_id exists"
                    ),
                    data=None,
                    error=BaseError(
                        error_message="company/client_id  exists"
                    )
                )
                return ORJSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=_content.model_dump())
    
        

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

            institution_data = session.query(
                Institution
            ).filter(
                Institution.public_id==req_body.institution_id
            ).first()


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

            session.add(billing_data)

            if billing_mode_type_data.billing_mode_type == "PREPAID":
                wallet_data = Wallet(
                    company_id = company_data.company_id,
                    amount = 0.0,
                    ledger_amount = 0.0,
                )
                session.add(wallet_data)

            bank_type_data = session.query(
                BankTypeMaster
            ).filter(
                BankTypeMaster.public_id==req_body.bank_type_id
            ).first()

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

            session.add(company_banking_data)
            
            session.flush()

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

            _successful, _message, _error, _status_code = True, "created client", None, status.HTTP_200_OK

            
        elif role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value: 
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
    
        session.commit()

        if company_data:
            company_data = Company_MF.model_validate(company_data).model_dump()  
                    
            # if company_data.get("billing_information",{}).get("volume_tariff"):
            #     company_data["billing_information"]["volume_tariff"] = [ VolumeTariff_MF.model_validate(i).model_dump() for i in company_data["billing_information"]["volume_tariff"] ] 
            # if company_data.get("billing_information",{}).get("institution",{}) and company_data.get("billing_information",{}).get("institution",{}).get("volume_tariff") :
            #     company_data["billing_information"]["institution"]["volume_tariff"] = [ VolumeTariff_MF.model_validate(i).model_dump() for i in company_data["billing_information"]["institution"]["volume_tariff"] ] 


        _data = company_data # company_data.to_dict()
    
        exclude_data_keys = ("company_id", "billing_id","billing_information.billing_frequency_id","billing_information.billing_id","billing_information.currency_id","billing_information.currency.currency_id","billing_information.billing_frequency.billing_frequency_id","banking_info.company_id","banking_info.bank_type_id","banking_info.bank_type.bank_type_id")
        remove_keys_from_dict(_data,exclude_data_keys)

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


# # Update Company /company /company/billing /company/banking
@api.put("/company/{company_id}")
def update_company(
    *,
    company_id:str=Path(...),
    req_body:UpdateCompanyRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    _id = str(uuid.uuid4())

    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:

        if role_id == PortalRole.SUPER_ADMIN.value:
            company_data = session.query(Company).filter(Company.public_id == company_id).first()
            company_data.company_name = req_body.company_name
            company_data.client_id = req_body.client_id
            company_data.is_active = req_body.is_active

            try:
                session.flush()
            except sqlalchemy.exc.IntegrityError as e:
                _content = BaseResponse(
                    meta=BaseMeta(
                        _id=_id,
                        successful=False,
                        message="company/client_id exists"
                    ),
                    data=None,
                    error=BaseError(
                        error_message="company/client_id  exists"
                    )
                )
                return ORJSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=_content.model_dump())
    
            _successful, _message, _data, _error, _status_code = True, "updated", company_data, None, status.HTTP_200_OK

        elif role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value: 
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
    
        session.commit()
    
        if company_data:
            company_data = Company_MF.model_validate(company_data).model_dump()  
                    
            # if company_data.get("billing_information",{}).get("volume_tariff"):
            #     company_data["billing_information"]["volume_tariff"] = [ VolumeTariff_MF.model_validate(i).model_dump() for i in company_data["billing_information"]["volume_tariff"] ] 
            # if company_data.get("billing_information",{}).get("institution",{}) and company_data.get("billing_information",{}).get("institution",{}).get("volume_tariff") :
            #     company_data["billing_information"]["institution"]["volume_tariff"] = [ VolumeTariff_MF.model_validate(i).model_dump() for i in company_data["billing_information"]["institution"]["volume_tariff"] ] 

        _data = company_data

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


@api.put("/company/{company_id}/billing")
def update_company_billing(
    *,
    company_id:str=Path(...),
    req_body:UpdateCompanyBillingRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    _id = str(uuid.uuid4())

    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:

        if role_id == PortalRole.SUPER_ADMIN.value:
            # company_data = session.query(Company).filter(Company.public_id == company_id).first()

            company_data, billing_data = session.query(
                Company,
                BillingInformation
            ).join(
                Company,
                BillingInformation.company_id == Company.company_id
            ).filter(
                Company.public_id==company_id
            ).first()

            billing_frequency_data = session.query(BillingFrequencyMaster).filter(BillingFrequencyMaster.public_id == req_body.billing_frequency_id).first()
            billing_mode_type_data = session.query(BillingModeTypeMaster).filter(BillingModeTypeMaster.public_id==req_body.billing_mode_type_id).first()
            institution_data = session.query(Institution).filter(Institution.public_id==req_body.institution_id).first()

            billing_data.email_id1=req_body.email_id1
            billing_data.floor_cost=req_body.floor_cost
            billing_data.vat=req_body.vat 
            # currency_id:Optional[float]
            billing_data.billing_start_date=req_body.billing_start_date
            billing_data.billing_end_date=req_body.billing_end_date
            billing_data.billing_frequency_id=billing_frequency_data.billing_frequency_id
            billing_data.billing_mode_type_id=billing_mode_type_data.billing_mode_type_id
            billing_data.institution_id=institution_data.institution_id if institution_data else None

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

            _successful, _message, _data, _error, _status_code = True, "updated", company_data, None, status.HTTP_200_OK

        elif role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value: 
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

        session.flush()
        session.commit()

        # company_data = session.query(Company).filter(Company.public_id == company_id).first()

        if company_data:
            company_data = Company_MF.model_validate(company_data).model_dump()  
                    

        _data = company_data

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


@api.put("/company/{company_id}/banking")
def update_company_banking(
    *,
    company_id:str=Path(...),
    req_body:UpdateCompanyBankingRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):

    _id = str(uuid.uuid4())

    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:

        if role_id == PortalRole.SUPER_ADMIN.value:
            # company_data = session.query(Company).filter(Company.public_id == company_id).first()

            company_data, banking_data = session.query(
                Company,
                CompanyBankingInfo
            ).join(
                CompanyBankingInfo,
                CompanyBankingInfo.company_id == Company.company_id
            ).filter(
                Company.public_id==company_id
            ).first()

            bank_type_data = session.query(BankTypeMaster).filter(BankTypeMaster.public_id == req_body.bank_type_id).first()

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


            _successful, _message, _data, _error, _status_code = True, "updated", company_data, None, status.HTTP_200_OK

        elif role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value: 
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
    
        session.commit()
    
        if company_data:
            company_data = Company_MF.model_validate(company_data).model_dump()  
                    
            # if company_data.get("billing_information",{}).get("volume_tariff"):
            #     company_data["billing_information"]["volume_tariff"] = [ VolumeTariff_MF.model_validate(i).model_dump() for i in company_data["billing_information"]["volume_tariff"] ] 
            # if company_data.get("billing_information",{}).get("institution",{}) and company_data.get("billing_information",{}).get("institution",{}).get("volume_tariff") :
            #     company_data["billing_information"]["institution"]["volume_tariff"] = [ VolumeTariff_MF.model_validate(i).model_dump() for i in company_data["billing_information"]["institution"]["volume_tariff"] ] 


        _data = company_data

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

# Delete Company
@api.delete("/company/{company_id}")
def delete_company(
    *,

    company_id:str=Path(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    _id = str(uuid.uuid4())
    role_id =  decoded_token.get("rid")

    
    with database_client.Session() as session:

        if role_id == PortalRole.SUPER_ADMIN.value:
            company_data = session.query(
                Company
            ).filter(
                Company.public_id == company_id
            )

        elif role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value:

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

        company_data = company_data.first()

        if not company_data:
            _successful, _message, _error, _status_code = False, "user not found", BaseError(error_message="user not found"), status.HTTP_404_NOT_FOUND
        else:
            
            company_banking_data = session.query(CompanyBankingInfo).filter(CompanyBankingInfo.company_id == company_data.company_id).first()
            if company_banking_data:
                session.delete(company_banking_data)

            session.delete(company_data)
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

# Wallet
@api.get("/company/{company_id}/wallet")
def wallet(
    *,
    company_id:str=Path(...),

    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    _id = str(uuid.uuid4())
    role_id =  decoded_token.get("rid")

    with database_client.Session() as session:


        wallet_data = session.query(
            Wallet
        ).join(
            Company,
            Wallet.company_id == Company.company_id
        ).filter(
            Company.public_id==company_id
        ).first()


        if role_id == PortalRole.SUPER_ADMIN.value or role_id == PortalRole.ADMIN.value or role_id == PortalRole.EXPLORER.value: # SUPER ADMIN
            ...
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
        

        if wallet_data:
            wallet_data = wallet_data.to_dict()

            _successful, _message, _data, _error, _status_code = True, None, wallet_data, None, status.HTTP_200_OK
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

@api.post("/company/{company_id}/wallet/load_wallet")
async def load_wallet(
    *,
    company_id:str=Path(...),
    # amount:int = Body(...),

    decoded_token:dict = Depends(decodeJwtTokenDependancy),
    request:Request,
):
    _id = str(uuid.uuid4())
    role_id =  decoded_token.get("rid")

    amount = (await request.json()).get('amount')
    

    with database_client.Session() as session:


        wallet_data = session.query(
            Wallet
        ).join(
            Company,
            Wallet.company_id == Company.company_id
        ).filter(
            Company.public_id==company_id
        ).first()


        if role_id == PortalRole.SUPER_ADMIN.value or role_id == PortalRole.ADMIN.value: # SUPER ADMIN
            ...
        elif role_id == PortalRole.EXPLORER.value: 
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
        

        if wallet_data:
            wallet_data.amount += amount
            wallet_data.ledger_amount += amount
            session.flush()
            session.commit()
            _successful, _message, _data, _error, _status_code = True, None, wallet_data.to_dict(), None, status.HTTP_200_OK
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
    _id = str(uuid.uuid4())
    # get role id of logged in user
    role_id =  decoded_token.get("rid")


    # check if non super admin + company_id == all or company_id != cid
    # if not (role_id != PortalRole.SUPER_ADMIN.value and (company_id != decoded_token.get("cid"))) and role_id in (_.value for _ in PortalRole)  :
    if role_id == PortalRole.SUPER_ADMIN.value:

        # create session with db
        with database_client.Session() as session:

            # setup non verbose data
            non_verbose_data = (Institution.public_id.label("institution_id"), Institution.institution_name)
            data_to_query = (Institution,) if x_verbose else non_verbose_data

            # basic query
            query = session.query( *data_to_query )

            
            # get total count for pagination
            total_count = session.query(func.count()).select_from(Institution).scalar()

            # pagination
            if not x_ignore_pagination:
                offset = (page_no - 1) * items_per_page
                query = query.order_by(Institution.create_date).offset(offset).limit(items_per_page)

            # get all data
            institution_data = query.all()

            if institution_data:
                # format data
                institution_data = [  Institution_MF.model_validate(i).model_dump() if x_verbose else i._asdict() for i in institution_data  ]
                
                # if x_verbose:
                #     for idx, _ in enumerate(institution_data):
                #         institution_data[idx]["volume_tariff"] = [ VolumeTariff_MF.model_validate(i).model_dump() for i in institution_data[idx]["volume_tariff"]] if institution_data[idx]["volume_tariff"] else None


                # institution_data = [  i.to_dict() if x_verbose else i._asdict() for i in institution_data  ]

        _response = PaginationResponse
        _pagination_data = PaginationData(items_per_page=items_per_page, page_no=page_no, total_count=total_count, page_url=request.url._url )
        _meta = PaginationMeta(_id=_id, successful=True, message=None, pagination_data=_pagination_data)
        _data = institution_data
        _error = None
        _status_code = status.HTTP_200_OK

    else:

        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message="unauthorized")
        _data = None
        _error = BaseError(error_message="unauthorized")
        _status_code = status.HTTP_403_FORBIDDEN

    
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
    _id = str(uuid.uuid4())
    # get role id of logged in user
    role_id =  decoded_token.get("rid")


    # check if non super admin + company_id == all or company_id != cid
    # if not (role_id != PortalRole.SUPER_ADMIN.value and (company_id != decoded_token.get("cid"))) and role_id in (_.value for _ in PortalRole)  :
    if role_id == PortalRole.SUPER_ADMIN.value:

        # create session with db
        with database_client.Session() as session:


            # basic query
            query = session.query( Institution ).options(joinedload(Institution.volume_tariff)).filter(Institution.public_id == institution_id )

            # get all data
            institution_data = query.first()
            
            if institution_data:
                institution_data = Institution_MF.model_validate(institution_data).model_dump()
                # institution_data["volume_tariff"] =  [ VolumeTariff_MF.model_validate(i).model_dump() for i in institution_data["volume_tariff"] ] if institution_data["volume_tariff"] else None
                # institution_data = institution_data.to_dict()
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message=None)
                _data = institution_data
                _error = None
                _status_code = status.HTTP_200_OK
            else:
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message="istitution not found")
                _data = None
                _error = BaseError(error_message="istitution not found")
                _status_code = status.HTTP_404_NOT_FOUND                

    else:

        _response = BaseResponse
        _meta = BaseMeta(_id=_id, successful=False, message="unauthorized")
        _data = None
        _error = BaseError(error_message="unauthorized")
        _status_code = status.HTTP_403_FORBIDDEN

    
    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    
# POST Institution

@api.post("/institution")
def create_institution(
    *,
    req_body:CreateInstitutionRequest=Body(...),
    decoded_token:dict = Depends(decodeJwtTokenDependancy),
):
    # create request id
    _id = str(uuid.uuid4())
    # get role id of logged in user
    role_id =  decoded_token.get("rid")

    # create session with db
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

        # cheeck if role is valid or admin using differnt cid
        # if ( role_id not in (PortalRole.SUPER_ADMIN.value, PortalRole.ADMIN.value) ) or (role_id == PortalRole.ADMIN.value and decoded_token.get("cid") != company_data.public_id):
        if ( role_id not in (PortalRole.SUPER_ADMIN.value) ):

            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message="unauthorized")
            _data = None
            _error = BaseError(error_message="unauthorized")
            _status_code = status.HTTP_403_FORBIDDEN

        else:
            # create employee object
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
                # add employee to db
                session.add(institution_data)
                #session.refresh(institution_data)
                session.flush()

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

                session.commit()
                session.refresh(institution_data)

                institution_data = Institution_MF.model_validate(institution_data).model_dump()
                # institution_data["volume_tariff"] =  [ VolumeTariff_MF.model_validate(i).model_dump() for i in institution_data["volume_tariff"] ] if institution_data["volume_tariff"] else None
                
                
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message="created")
                _data = institution_data
                _error = None
                _status_code = status.HTTP_200_OK
            except sqlalchemy.exc.IntegrityError as e:

                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message="user exists")
                _data = None
                _error = BaseError(error_message="user exists")
                _status_code = status.HTTP_400_BAD_REQUEST


    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())
    
# PUT Institution
@api.put("/institution/{institution_id}")
def update_institution(
    *,
    institution_id: str = Path(...),
    req_body: UpdateInstitutionRequest = Body(...),
    decoded_token: dict = Depends(decodeJwtTokenDependancy),
):
    # create request id
    _id = str(uuid.uuid4())
    # get role id of logged in user
    role_id = decoded_token.get("rid")

    # create session with db
    with database_client.Session() as session:

        # check if user has permission
        if role_id != PortalRole.SUPER_ADMIN.value:
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message="unauthorized")
            _data = None
            _error = BaseError(error_message="unauthorized")
            _status_code = status.HTTP_403_FORBIDDEN
        else:
            # retrieve the institution to be updated
            institution_data = session.query(Institution).filter(Institution.public_id == institution_id).first()
            billing_frequency_data = session.query(BillingFrequencyMaster).filter(BillingFrequencyMaster.public_id == req_body.billing_frequency_id).first()
            billing_mode_type_data = session.query(BillingModeTypeMaster).filter(BillingModeTypeMaster.public_id==req_body.billing_mode_type_id).first()

            if institution_data:
                # update institution data
                institution_data.institution_name = req_body.institution_name
                institution_data.floor_cost = req_body.floor_cost
                institution_data.vat = req_body.vat
                institution_data.billing_start_date = req_body.billing_start_date
                institution_data.billing_end_date = req_body.billing_end_date
                institution_data.billing_frequency_id=billing_frequency_data.billing_frequency_id
                institution_data.billing_mode_type_id=billing_mode_type_data.billing_mode_type_id
                # commit the changes to the database

                volume_tariff_data = session.query(
                    VolumeTariff
                ).filter(
                    VolumeTariff.institution_id == institution_data.institution_id
                ).all()

                if volume_tariff_data:
                    for vt in volume_tariff_data:
                        session.delete(vt)
                
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

                session.flush()
                session.commit()

                institution_data = Institution_MF.model_validate(institution_data).model_dump()
                # institution_data["volume_tariff"] =  [ VolumeTariff_MF.model_validate(i).model_dump() for i in institution_data["volume_tariff"] ] if institution_data["volume_tariff"] else None
                

                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message="updated")
                _data = institution_data
                _error = None
                _status_code = status.HTTP_200_OK
            else:
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message="institution not found")
                _data = None
                _error = BaseError(error_message="institution not found")
                _status_code = status.HTTP_404_NOT_FOUND

    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())

# Delete INSTITUTIon
@api.delete("/institution/{institution_id}")
def delete_institution(
    *,
    institution_id: str = Path(...),
    decoded_token: dict = Depends(decodeJwtTokenDependancy),
):
    # create request id
    _id = str(uuid.uuid4())
    # get role id of logged in user
    role_id = decoded_token.get("rid")

    # create session with db
    with database_client.Session() as session:

        # check if user has permission
        if role_id != PortalRole.SUPER_ADMIN.value:
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message="unauthorized")
            _data = None
            _error = BaseError(error_message="unauthorized")
            _status_code = status.HTTP_403_FORBIDDEN
        else:
            # retrieve the institution to be deleted
            institution_data = session.query(Institution).filter(Institution.public_id == institution_id).first()

            if institution_data:
                # delete institution from the database
                session.delete(institution_data)
                session.commit()

                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message="deleted")
                _data = None
                _error = None
                _status_code = status.HTTP_200_OK
            else:
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message="institution not found")
                _data = None
                _error = BaseError(error_message="institution not found")
                _status_code = status.HTTP_404_NOT_FOUND

    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())

# volume tarrif
@api.post("/volume_tariff")
def volume_tariff(
    *,
    x_id_type: str = Header("institution", alias="x-id-type"),
    req_body:AddVolumeTariffRequest=Body(...),
    decoded_token: dict = Depends(decodeJwtTokenDependancy),
):

    # create request id
    _id = str(uuid.uuid4())
    # get role id of logged in user
    role_id = decoded_token.get("rid")

    # create session with db
    with database_client.Session() as session:

        # check if user has permission
        if role_id != PortalRole.SUPER_ADMIN.value:
            _response = BaseResponse
            _meta = BaseMeta(_id=_id, successful=False, message="unauthorized")
            _data = None
            _error = BaseError(error_message="unauthorized")
            _status_code = status.HTTP_403_FORBIDDEN
        else:

            if x_id_type == "company":
                _institution_id = None
                billing_data = session.query(BillingInformation).join(Company,Company.company_id==BillingInformation.company_id).filter(Company.public_id==req_body.item_id).first()
                _billing_id = billing_data.billing_id
            elif x_id_type == "institution":
                institution_data = session.query(Institution).filter(Institution.public_id==req_body.item_id).first()
                _billing_id = None
                _institution_id = institution_data.institution_id


            if _institution_id or _billing_id:

                volume_tariff_data = VolumeTariff(
                    institution_id = _institution_id,
                    billing_id = _billing_id,
                    min_volume = req_body.min_vol,
                    max_volume = req_body.max_vol,
                    rate = req_body.rate
                )

                # delete institution from the database
                session.add(volume_tariff_data)
                session.commit()

                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=True, message="created")
                _data = volume_tariff_data.to_dict()
                _error = None
                _status_code = status.HTTP_200_OK
            else:
                _response = BaseResponse
                _meta = BaseMeta(_id=_id, successful=False, message="institution/company not found")
                _data = None
                _error = BaseError(error_message="institution/company not found")
                _status_code = status.HTTP_404_NOT_FOUND

    _content = _response(meta=_meta, data=_data, error=_error)
    return ORJSONResponse(status_code=_status_code, content=_content.model_dump())

