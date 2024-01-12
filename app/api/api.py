#############
## Imports ##
#############

import io
import uuid
import csv
import datetime


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
                NFaceLogs,
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

    company_id:str=Query("all"),
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


        query = query.filter(Invoice.create_date >= start_datetime,
                                Invoice.create_date <= end_datetime)


        offset = (page_no - 1) * items_per_page
        query = query.order_by(Invoice.create_date).offset(offset).limit(items_per_page)

        query = query.all()
        if query:
            query = [ {**q[0].to_dict(), "bank_type":q[-1]} for q in query ]

    exclude_data_keys = ("invoice_id","company_id","company.company_id","company.billing_id","company.billing_information")
    for i in range(len(query)):
        remove_keys_from_dict(query[i],exclude_data_keys)


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
            dictify = lambda data,is_verbose : [i.to_dict() for i in data] if is_verbose else [i._asdict() for i in data]
            company_data = dictify(company_data, x_verbose)

            if x_verbose:
                exclude_data_keys = ("company_id", "company.billing_id","company.billing_information.billing_frequency_id","company.billing_information.billing_id","company.billing_information.currency_id","company.billing_information.currency.currency_id","company.billing_information.billing_frequency.billing_frequency_id","company.banking_info.company_id","company.banking_info.bank_type_id","company.banking_info.bank_type.bank_type_id")
                for i in range(len(company_data)):
                    remove_keys_from_dict(company_data[i],exclude_data_keys)

    
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
            company_data = company_data.filter(Company.public_id == company_id).first()
            dictify = lambda data,is_verbose : [i.to_dict() for i in [data]] if is_verbose else [i._asdict() for i in [data]]
            company_data = dictify(company_data, x_verbose)

            if x_verbose:
                exclude_data_keys = ("company_id", "billing_id","billing_information.billing_frequency_id","billing_information.billing_id","billing_information.currency_id","billing_information.currency.currency_id","billing_information.billing_frequency.billing_frequency_id","banking_info.company_id","banking_info.bank_type_id","banking_info.bank_type.bank_type_id")
                for i in range(len(company_data)):
                    remove_keys_from_dict(company_data[i],exclude_data_keys)

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

            billing_frequency_data = session.query(
                BillingFrequencyMaster
            ).filter(
                BillingFrequencyMaster.public_id==req_body.billing_frequency_id
            ).first()

            billing_data = BillingInformation(
                billing_info_name=f"reg_{req_body.company_name}",
                email_id1=req_body.email_id,
                fc_cpr=req_body.fc_cpr,
                pl_cpr=req_body.pl_cpr,
                floor_cost=req_body.floor_cost,
                currency_id=1,
                billing_start_date=req_body.billing_start_date,
                billing_end_date=req_body.billing_end_date,
                billing_frequency_id=billing_frequency_data.billing_frequency_id,
                is_public=0
            )

            session.add(billing_data)

            session.flush()


            company_data = Company(
                company_name=req_body.company_name,
                is_active=True,
                billing_id=billing_data.billing_id
            )

            session.add(company_data)

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
                gateway_client_id= req_body.gateway_client_id,
                institution_code= req_body.institution_code,
                billing_account_number= req_body.billing_account_number,
                billing_bank_code= req_body.billing_bank_code,
                billing_account_name= req_body.billing_account_name,
            )

            session.add(company_banking_data)
            
            session.flush()

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


        _data = company_data.to_dict()
    
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
            company_data.is_active = req_body.is_active
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
    
        _data = _data.to_dict()
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
                BillingInformation.billing_id == Company.billing_id
            ).filter(
                Company.public_id==company_id
            ).first()

            billing_frequency_data = session.query(BillingFrequencyMaster).filter(BillingFrequencyMaster.public_id == req_body.billing_frequency_id).first()

            billing_data.email_id1=req_body.email_id1
            billing_data.fc_cpr=req_body.fc_cpr
            billing_data.pl_cpr=req_body.pl_cpr
            billing_data.floor_cost=req_body.floor_cost
            # currency_id:Optional[float]
            billing_data.billing_start_date=req_body.billing_start_date
            billing_data.billing_end_date=req_body.billing_end_date
            billing_data.billing_frequency_id=billing_frequency_data.billing_frequency_id
            # is_public:Optional[bool]


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
    
        _data = _data.to_dict()
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
            banking_data.gateway_client_id=req_body.gateway_client_id
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
    
        _data = _data.to_dict()
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
