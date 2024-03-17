#############
## Imports ##
#############

import datetime

import pytest
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import relationship
import sqlalchemy_serializer

import redis

import requests

from jose import jwt

##############
## Settings ##
##############


@pytest.fixture
def client_fixture(monkeypatch):

    global app, database_client, email_client, otp_client, redis_client , decode_jwt_token_dependancy, PortalRole

    # SQL ALCHEMY MOCKS

    # Patch sqlalchemy metadata
    monkeypatch.setattr(sqlalchemy, "create_engine", MagicMock())
    # Patch sqlalchemy metadata
    monkeypatch.setattr(sqlalchemy, "MetaData", MagicMock())
    # Patch sqlalchemy relationship
    monkeypatch.setattr(relationship, "__call__", lambda *args, **kwargs: MagicMock())
    # Patch sqlalchemy declarative_base/
    monkeypatch.setattr("sqlalchemy.orm.declarative_base", MagicMock())
    # Patch sqlalchemy sessionmaker
    monkeypatch.setattr("sqlalchemy.orm.sessionmaker", MagicMock())
    # Patch sqlalchemy selectinload
    monkeypatch.setattr("sqlalchemy.orm.selectinload", MagicMock())
    # Patch sqlalchemy joinedload
    monkeypatch.setattr("sqlalchemy.orm.joinedload", MagicMock())
    # Patch sqlalchemy aliased
    monkeypatch.setattr("sqlalchemy.orm.aliased", MagicMock())
    # Patch sqlalchemy_serializer SerializerMixin
    monkeypatch.setattr(sqlalchemy_serializer, "SerializerMixin", MagicMock())

    # REDIS MOCKS

    # Patch Redis
    monkeypatch.setattr(redis, "from_url", MagicMock())

    # REQUESTS MOCK

    # Patch requests get
    monkeypatch.setattr(requests, "get", MagicMock())
    # Patch requests post
    monkeypatch.setattr(requests, "post", MagicMock())
    # Patch requests delete
    monkeypatch.setattr(requests, "delete", MagicMock())

    from app import app, database_client, email_client, otp_client, redis_client, config
    from app.utils.dependencies import decode_jwt_token_dependancy
    from app.utils.schema import PortalRole

    config.env_type="unit-test"


    with TestClient(app) as client:
        yield client

    config.env_type="prod"

SUPER_ADMIN_ID = "ECE70147-BE8A-43E4-9E19-350B8EC2DB8A"
ADMIN_ID = "6E5D878B-FC83-4508-988B-1D40D54EB1DA"
EXPLORER_ID = "BA398889-B22A-4CCB-A27D-7FBBC610FE92"

base_url="/nface/portal/api"


###########
## Tests ##
###########



@pytest.mark.parametrize(
    "req_body, msauth_return_status_code, db_return_data, expected_response_status_code",
    [
        ({"email_id": "test@example.com", "password": "password", "msauth_token":None}, None, {"password":b'$2b$12$ty7M6A/jbJ.i4/y1r3fy3OaHO9H.84OMGpRKuEEB/pL/imZlOHaBq'}, 200),
        ({"email_id": "test@example.com", "password": "wrong-password", "msauth_token":None}, None, {"password":b'$2b$12$ty7M6A/jbJ.i4/y1r3fy3OaHO9H.84OMGpRKuEEB/pL/imZlOHaBq'}, 401),
        ({"email_id": None, "password": None, "msauth_token":"token"}, 200, None, 200),
        ({"email_id": None, "password": None, "msauth_token":"wrong-token"}, 403, None, 401),
        ("None", None, None, 400),
    ],
    ids=["Login Success", "Login Fail", "MS Auth Login Success", "MS Auth Login Fail", "Bad Request"]
)
def test_login(client_fixture, monkeypatch, req_body, msauth_return_status_code, db_return_data, expected_response_status_code):

    user_password = db_return_data.get("password") if db_return_data else None

    # Mock Requests
    mocked_msauth_response = MagicMock(status_code=msauth_return_status_code)
    mocked_msauth_response.json.return_value = {"emails":["test@example.com"],"message":"message"}
    monkeypatch.setattr(requests, "get", MagicMock(return_value=mocked_msauth_response))

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    employee_data = MagicMock(password=user_password, is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1))
    mock_first.return_value = employee_data

    # Mock Pydantic Model Formatters

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": user_password,
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    }

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.EmployeeMF", mocked_formatter)


    # Make a request with valid credentials
    response = client_fixture.post(f"{base_url}/login", json=req_body)

    # Assert response
    assert response.status_code == expected_response_status_code



@pytest.mark.parametrize(
    "req_body, is_active, expected_response_status_code",
    [
        ({"email_id": "test@example.com",} , 1, 200),
        ({"email_id": "test@example.com",} , 0, 401),
    ],
    ids=["Verification Code Sent", "Unathorized",]
)
def test_forgot_password(client_fixture, monkeypatch, req_body, is_active, expected_response_status_code):

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    # monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_query.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    employee_data = MagicMock(password="", is_active=is_active, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1))
    mock_first.return_value = employee_data

    # Mock OTP client
    mock_verification_code = "123456"
    monkeypatch.setattr(otp_client, "create_verification_code", MagicMock(return_value=mock_verification_code))

    # Mock email client
    mock_send_mail = MagicMock()
    monkeypatch.setattr(email_client, "send_mail", mock_send_mail)

    # Make a request with a valid email
    response = client_fixture.post(f"{base_url}/forgot_password", json=req_body)

    # Assert response
    assert response.status_code == expected_response_status_code


@pytest.mark.parametrize(
    "req_body, expected_response_status_code",
    [
        ({"email_id":"","code":"12356","new_password":""} , 200),
        ({"email_id":"","code":"1236","new_password":""} , 401),
    ],
    ids=["Password Reset", "Invalid Credentials",]
)
def test_reset_password(client_fixture, monkeypatch, req_body, expected_response_status_code):

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    # monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_query.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    verification_data = MagicMock(_code="12356", create_date=datetime.datetime.now())
    mock_first.return_value = verification_data


    # Make a request with a valid email
    response = client_fixture.post(f"{base_url}/reset_password", json=req_body)

    # Assert response
    assert response.status_code == expected_response_status_code


def test_roles(client_fixture, monkeypatch):

    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":-1})

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_filter = MagicMock()
    mock_all = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_all)

    # Create a dictionary to represent the return value of session.query.first()
    employee_data = MagicMock(password="", is_active=1, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1))
    mock_all.return_value = employee_data


    # Patch model_validate and model_dump methods
    mock_employee_processed = {

        "role": {"role_id": -1}
    }

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.RolesMF", mocked_formatter)

    # Make a request with valid credentials
    response = client_fixture.get(f"{base_url}/roles", headers={"x-verbose":"true","x-access-token":"s"} )

    # Assert response
    assert response.status_code == 200


@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID, 200),
        (EXPLORER_ID, 403),
    ],
    ids=["Retrieve Employees", "Unauthorized",]
)
def test_get_all_employees(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})


    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    employee_data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1))
    mock_first.return_value = employee_data

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    }

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.EmployeeMF", mocked_formatter)


    # Make a request with valid credentials
    params = {"company_id":"all","page_no":1,"items_per_page":2,"search":"ry"}
    headers = {"x-access-token":"abc"}
    response = client_fixture.get(f"{base_url}/employees", params=params, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code


@pytest.mark.parametrize(
    "role_id, employee_data, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,{"password":""}, 200),
        (ADMIN_ID,{"password":""}, 200),
        (SUPER_ADMIN_ID, None, 404),
        (-1, None, 403),
    ],
    ids=["Retrieve Employee as SUPER_ADMIN", "Retrieve Employee as ADMIN", "Employee Not Found", "Unauthorized",]
)
def test_get_employee(client_fixture, monkeypatch, role_id, employee_data, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})


    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    employee_data = MagicMock(password=employee_data.get("password"), is_active=employee_data.get("is_active"), employee_id=employee_data.get("employee_id"), company=MagicMock(company_id=employee_data.get("company_id")), role=MagicMock(role_id=employee_data.get("role_id"))) if employee_data else None
    mock_first.return_value = employee_data

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } if employee_data else None

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.EmployeeMF", mocked_formatter)


    # Make a request with valid credentials
    params = {"company_id":"BBACBAB6-C18C-4C76-8838-E8590B932A5A","page_no":1,"items_per_page":2,"search":"ry"}
    headers = {"x-access-token":"abc"}
    response = client_fixture.get(f"{base_url}/employee/abc", params=params, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code



@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID, 200),
        (EXPLORER_ID, 403),
    ],
    ids=["Create Employee", "Unauthorized",]
)
def test_create_employee(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})


    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    employee_data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1))
    mock_first.return_value = employee_data

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    }

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.EmployeeMF", mocked_formatter)


    # Make a request with valid credentials
    req_body = {
        "email_id":"abcsssssw2@kg.com",
        "password":"str",
        "employee_name":"abc",
        "phone_number":"123",
        "employee_profile_pic":None,
        "company_id":"F574760A-811E-41ED-87FB-822F7EBDF8B7",
        "role_id":"BA398889-B22A-4CCB-A27D-7FBBC610FE92"
    }
    headers = {"x-access-token":"abc"}
    response = client_fixture.post(f"{base_url}/employee", json=req_body, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code



@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID, 200),
        (ADMIN_ID, 200),
        (-1, 403),
    ],
    ids=["Modified Employee as SUPER_ADMIN", "Modified Employee as ADMIN", "Unauthorized",]
)
def test_modify_employee(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})


    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    employee_data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1))
    mock_first.return_value = employee_data

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    }

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.EmployeeMF", mocked_formatter)


    # Make a request with valid credentials
    req_body = {
        "employee_name":"Alex",
        "phone_number":"123",
        "employee_profile_pic":None,
        "is_active":False
    }
    headers = {"x-access-token":"abc"}
    response = client_fixture.put(f"{base_url}/employee/abc", json=req_body, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code


@pytest.mark.parametrize(
    "role_id, employee_not_found, expected_response_status_code",
    [
        (SUPER_ADMIN_ID, False, 200),
        (ADMIN_ID, False, 200),
        # (SUPER_ADMIN_ID, True, 404),
        (-1, False, 403),
    ],
    ids=["Update Password as SUPER_ADMIN", "Update Password as ADMIN", "Unauthorized",]
)
def test_update_password(client_fixture, monkeypatch, role_id, employee_not_found, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})


    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    # monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_query.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    employee_data = MagicMock(password=b"abc", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), password_old_1=None, password_old_2=None, password_old_3=None, password_old_4=None, password_old_5=None, password_old_6=None, password_old_7=None, password_old_8=None, password_old_9=None, password_old_10=None, password_old_11=None, password_old_12=None)
    mock_first.return_value = employee_data

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } if not employee_not_found else None

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.EmployeeMF", mocked_formatter)


    # Make a request with valid credentials
    req_body = {
        "old_password":"str",
        "new_password":"password11"
    }
    headers = {"x-access-token":"abc"}
    response = client_fixture.put(f"{base_url}/employee/abc/update_password", json=req_body, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code



@pytest.mark.parametrize(
    "role_id, employee_not_found, expected_response_status_code",
    [
        (SUPER_ADMIN_ID, False, 200),
        (ADMIN_ID, False, 200),
        # (SUPER_ADMIN_ID, True, 404),
        (-1, False, 403),
    ],
    ids=["Delete Employee as SUPER_ADMIN", "Delete Employee as ADMIN", "Unauthorized",]
)
def test_delete_employee(client_fixture, monkeypatch, role_id, employee_not_found, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    employee_data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1)) if not employee_not_found else None
    mock_first.return_value = employee_data

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } if not employee_not_found else None

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.EmployeeMF", mocked_formatter)


    # Make a request with valid credentials
    headers = {"x-access-token":"abc"}
    response = client_fixture.delete(f"{base_url}/employee/abc", headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code




@pytest.mark.parametrize(
    "role_id, response_type, expected_response_status_code",
    [
        (SUPER_ADMIN_ID, "json", 200),
        # (SUPER_ADMIN_ID, "csv", 200),
        (SUPER_ADMIN_ID, "csv-transaction", 200),
        (-1, "json", 403),

    ],
    ids=["Read JSON Logs as SUPER_ADMIN", "Read CSV_Transaction Logs", "Unauthorized",]
)
def test_get_nface_logs(client_fixture, monkeypatch, role_id, response_type, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = _data

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.NFaceLogsMF", mocked_formatter)


    # Make a request with valid credentials
    params={
        "company_id":"all",
        "status_filter":"all",
        "service_filter":"all",
        "start_datetime":"2022-11-01 17:18:59.937",
        "end_datetime":"2025-11-01 17:18:59.937",
        "page_no":"1",
        "items_per_page":"5"
    }

    headers = {
        "x-access-token":"abc",
        "x-ignore-pagination":"true",
        "x-response-type":response_type
    }
    response = client_fixture.get(f"{base_url}/nface_logs", params=params, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code



@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,  200),
        (-1,  403),

    ],
    ids=["Read JSON Log Stats as SUPER_ADMIN", "Unauthorized",]
)
def test_get_nface_stats(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = _data

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.NFaceLogsMF", mocked_formatter)


    # Make a request with valid credentials
    params={
        "company_id":"all",
        "status_filter":"all",
        "service_filter":"all",
        "start_datetime":"2022-11-01 17:18:59.937",
        "end_datetime":"2025-11-01 17:18:59.937",
        "page_no":"1",
        "items_per_page":"5"
    }

    headers = {
        "x-access-token":"abc",
    }
    response = client_fixture.get(f"{base_url}/nface_logs/stats", params=params, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code



@pytest.mark.parametrize(
    "role_id, response_type, bank_type_filter,  expected_response_status_code",
    [
        (SUPER_ADMIN_ID, "json", "all", 200),
        (SUPER_ADMIN_ID, "csv", "all", 200),
        (SUPER_ADMIN_ID, "csv", "dmb", 200),
        (SUPER_ADMIN_ID, "csv", "non-dmb", 200),
        (ADMIN_ID, "json", "all", 403),

    ],
    ids=["Read JSON Invoice as SUPER_ADMIN", "Read CSV Invoice as Bank=ALL", "Read CSV Invoice as Bank=DMB", "Read CSV Invoice as Bank=NON-DMB", "Unauthorized",]
)
def test_get_invoice(client_fixture, monkeypatch, role_id, response_type, bank_type_filter,  expected_response_status_code):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = _data

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.end_date.__le__.return_value=True
    nfl_mock.end_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.Invoice", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.InvoiceMF", mocked_formatter)


    # Make a request with valid credentials
    params={
        "company_id": "all",
        "start_datetime": "2022-11-01 17:18:59.937",
        "end_datetime": "2025-11-01 17:18:59.937",
        "status_filter": "all",
        "bank_type_filter": bank_type_filter,
        "page_no": 1,
        "items_per_page": 100
    }
    headers = {
        "x-access-token":"abc",
        "x-ignore-pagination":"true",
        "x-response-type":response_type
    }
    response = client_fixture.get(f"{base_url}/invoice", params=params, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code



@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,  200),
        (ADMIN_ID,  403),

    ],
    ids=["Read JSON invoice Stats as SUPER_ADMIN", "Unauthorized",]
)
def test_get_invoive_stats(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = _data

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.NFaceLogsMF", mocked_formatter)


    # Make a request with valid credentials
    params={
        "company_id":"all",
        "start_datetime":"2022-11-01 17:18:59.937",
        "end_datetime":"2025-11-01 17:18:59.937"
    }

    headers = {
        "x-access-token":"abc",
    }
    response = client_fixture.get(f"{base_url}/invoice/stats", params=params, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code




@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,  200),
        (ADMIN_ID,  403),

    ],
    ids=["Read bank type as SUPER_ADMIN", "Unauthorized",]
)
def test_bank_type(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = _data

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.NFaceLogsMF", mocked_formatter)


    # Make a request with valid credentials
    params={
        "company_id":"all",
        "start_datetime":"2022-11-01 17:18:59.937",
        "end_datetime":"2025-11-01 17:18:59.937"
    }

    headers = {
        "x-access-token":"abc",
    }
    response = client_fixture.get(f"{base_url}/bank_type", params=params, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code




@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,  200),
        (ADMIN_ID,  403),

    ],
    ids=["Read billing frequency as SUPER_ADMIN", "Unauthorized",]
)
def test_billing_frequency(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = _data

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.NFaceLogsMF", mocked_formatter)


    # Make a request with valid credentials
    params={
        "company_id":"all",
        "start_datetime":"2022-11-01 17:18:59.937",
        "end_datetime":"2025-11-01 17:18:59.937"
    }

    headers = {
        "x-access-token":"abc",
    }
    response = client_fixture.get(f"{base_url}/billing_frequency", params=params, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code




@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,  200),
        (ADMIN_ID,  403),

    ],
    ids=["Read billing_mode_type as SUPER_ADMIN", "Unauthorized",]
)
def test_billing_mode_type(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = _data

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.NFaceLogsMF", mocked_formatter)


    # Make a request with valid credentials
    params={
        "company_id":"all",
        "start_datetime":"2022-11-01 17:18:59.937",
        "end_datetime":"2025-11-01 17:18:59.937"
    }

    headers = {
        "x-access-token":"abc",
    }
    response = client_fixture.get(f"{base_url}/billing_mode_type", params=params, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code




@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,  200),
        (ADMIN_ID,  403),

    ],
    ids=["Read company as SUPER_ADMIN", "Unauthorized",]
)
def test_get_all_companies(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = _data

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.NFaceLogsMF", mocked_formatter)


    # Make a request with valid credentials
    params={
        "company_id":"all",
        "start_datetime":"2022-11-01 17:18:59.937",
        "end_datetime":"2025-11-01 17:18:59.937"
    }

    headers = {
        "x-access-token":"abc",
    }
    response = client_fixture.get(f"{base_url}/company", params=params, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code




@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,  200),
        (ADMIN_ID,  403),

    ],
    ids=["Read company as SUPER_ADMIN", "Unauthorized",]
)
def test_get_company(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = _data

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.NFaceLogsMF", mocked_formatter)


    # Make a request with valid credentials
    params={
        "company_id":"all",
        "start_datetime":"2022-11-01 17:18:59.937",
        "end_datetime":"2025-11-01 17:18:59.937"
    }

    headers = {
        "x-access-token":"abc",
    }
    response = client_fixture.get(f"{base_url}/company/lk", params=params, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code



@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,  200),
        (ADMIN_ID,  403),

    ],
    ids=["Onboard Client as SUPER_ADMIN", "Unauthorized",]
)
def test_onboard_client(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = _data

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.CompanyMF", mocked_formatter)


    # Make a request with valid credentials
    data={
        "email_id":"temp@temp.com",
        "floor_cost":1000,
        "vat":1,
        "billing_start_date":"2025-11-01 17:26:24",
        "billing_end_date":"2025-11-01 17:26:24",
        "billing_frequency_id":"A100F48A-61DF-4EAA-99D9-7D074D066385",
        "company_name":"temptemp1k0wj92m2",
            "auto_disable_days":90,
        "bank_type_id":"8AD898F1-179A-4572-9F6A-2295D942B3A4",
        "routing_number":"temp",
        "product_code":"temp",
        "sort_code":"temp",
        "payee_beneficiary":"temp",
        "client_id":"j222jkw",
        "institution_code":"temp",
        "billing_account_number":"temp",
        "billing_bank_code":"temp",
        "billing_account_name":"temp",

        "billing_mode_type_id":"af5ceee7-ed22-4ccb-bd7d-0cc947f203ab",
        "institution_id":None,

            "volume_tariff":[
                {
                "min_vol":0,
                "max_vol":10,
                "rate":100
                },
                {
                "min_vol":11,
                "max_vol":100,
                "rate":10
                }
            ]
        }

    headers = {
        "x-access-token":"abc",
    }
    response = client_fixture.post(f"{base_url}/register_client", json=data, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code



@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,  200),
        (ADMIN_ID,  403),

    ],
    ids=["Update Company as SUPER_ADMIN", "Unauthorized",]
)
def test_update_company(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = _data

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.CompanyMF", mocked_formatter)


    # Make a request with valid credentials
    data= {
        "company_name":"temptemp9999",
        "client_id":"temp",
        "is_active":"true",
        "auto_disable_days":90
    }

    headers = {
        "x-access-token":"abc",
    }
    response = client_fixture.put(f"{base_url}/company/abc", json=data, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code



@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,  200),
        (ADMIN_ID,  403),

    ],
    ids=["Update Company Billing as SUPER_ADMIN", "Unauthorized",]
)
def test_update_company_billing(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "join", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = (_data, _data)

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.CompanyMF", mocked_formatter)


    # Make a request with valid credentials
    data= {
        "email_id1":"temp@temklklkp0.com",
        "floor_cost":1000,
        "vat":1,
        "billing_start_date":"2025-11-01 17:26:24",
        "billing_end_date":"2025-11-01 17:26:24",
        "billing_frequency_id":"A100F48A-61DF-4EAA-99D9-7D074D066385",
        "billing_mode_type_id":"af5ceee7-ed22-4ccb-bd7d-0cc947f203ab",
        "institution_id":None,
            "volume_tariff":[
                {
                "min_vol":0,
                "max_vol":100,
                "rate":100
                },
                {
                "min_vol":100,
                "max_vol":200,
                "rate":10
                }
            ]
    }
    headers = {
        "x-access-token":"abc",
    }
    response = client_fixture.put(f"{base_url}/company/abc/billing", json=data, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code


@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,  200),
        (ADMIN_ID,  403),

    ],
    ids=["Update Company Banking as SUPER_ADMIN", "Unauthorized",]
)
def test_update_company_banking(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "join", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = (_data, _data)

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.CompanyMF", mocked_formatter)


    # Make a request with valid credentials
    data= {
        "bank_type_id":"8AD898F1-179A-4572-9F6A-2295D942B3A4",
        "routing_number":"temp",
        "product_code":"temp",
        "sort_code":"temp",
        "payee_beneficiary":"temklklkp",
        "institution_code":"temp",
        "billing_account_number":"temp",
        "billing_bank_code":"temp",
        "billing_account_name":"temp"
    }
    headers = {
        "x-access-token":"abc",
    }
    response = client_fixture.put(f"{base_url}/company/abc/banking", json=data, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code



@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,  200),
        (ADMIN_ID,  403),

    ],
    ids=["Delete company as SUPER_ADMIN", "Unauthorized",]
)
def test_delete_company(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = _data

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.InstitutionMF", mocked_formatter)


    # Make a request with valid credentials
    data= {}
    headers = {
        "x-access-token":"abc",
    }
    response = client_fixture.delete(f"{base_url}/company/abc", headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code




@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,  200),
        (ADMIN_ID,  403),

    ],
    ids=["Read institutions as SUPER_ADMIN", "Unauthorized",]
)
def test_get_institutions(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = _data

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.NFaceLogsMF", mocked_formatter)


    # Make a request with valid credentials
    params={
        "page_no":1,
        "items_per_page":100
    }

    headers = {
        "x-access-token":"abc",
    }
    response = client_fixture.get(f"{base_url}/institutions", params=params, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code




@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,  200),
        (ADMIN_ID,  403),

    ],
    ids=["Read institutions as SUPER_ADMIN", "Unauthorized",]
)
def test_get_institution(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = _data

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.InstitutionMF", mocked_formatter)


    # Make a request with valid credentials
    params={
        "page_no":1,
        "items_per_page":100
    }

    headers = {
        "x-access-token":"abc",
    }
    response = client_fixture.get(f"{base_url}/institution/abc", params=params, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code





@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,  200),
        (ADMIN_ID,  403),

    ],
    ids=["Create institutions as SUPER_ADMIN", "Unauthorized",]
)
def test_create_institution(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = _data

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.InstitutionMF", mocked_formatter)


    # Make a request with valid credentials
    data={
        "institution_name":"str",
        "floor_cost":0,
        "vat":1,
        "billing_start_date":"2025-11-01 17:26:24",
        "billing_end_date":"2025-11-01 17:26:24",
        "billing_frequency_id":"A100F48A-61DF-4EAA-99D9-7D074D066385",
        "billing_mode_type_id":"af5ceee7-ed22-4ccb-bd7d-0cc947f203ab",
        "volume_tariff":[
            {
            "min_vol":0,
            "max_vol":10,
            "rate":100
            },
            {
            "min_vol":11,
            "max_vol":100,
            "rate":10
            }
        ]
    }

    headers = {
        "x-access-token":"abc",
    }
    response = client_fixture.post(f"{base_url}/institution", json=data, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code




@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,  200),
        (ADMIN_ID,  403),

    ],
    ids=["Update institutions as SUPER_ADMIN", "Unauthorized",]
)
def test_update_institution(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = _data

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.InstitutionMF", mocked_formatter)


    # Make a request with valid credentials
    data= {
        "institution_name":"str2",
        "floor_cost":0,
        "vat":1,
        "billing_start_date":"2025-11-01 17:26:24",
        "billing_end_date":"2025-11-01 17:26:24",
        "billing_frequency_id":"A100F48A-61DF-4EAA-99D9-7D074D066385",
        "billing_mode_type_id":"af5ceee7-ed22-4ccb-bd7d-0cc947f203ab",
        "volume_tariff":[
            {
            "min_vol":0,
            "max_vol":100,
            "rate":100
            },
            {
            "min_vol":100,
            "max_vol":200,
            "rate":10
            }
        ]
    }

    headers = {
        "x-access-token":"abc",
    }
    response = client_fixture.put(f"{base_url}/institution/abc", json=data, headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code



@pytest.mark.parametrize(
    "role_id, expected_response_status_code",
    [
        (SUPER_ADMIN_ID,  200),
        (ADMIN_ID,  403),

    ],
    ids=["Delete institutions as SUPER_ADMIN", "Unauthorized",]
)
def test_delete_institution(client_fixture, monkeypatch, role_id, expected_response_status_code ):
    # Mock JWT
    monkeypatch.setattr(jwt, "decode", lambda *args,**kwargs: {"cid":-1, "uid":-1,"rid":role_id})

    # Mock Database Queries

    # Create MagicMock instances for each intermediate object in the chain
    mock_query = MagicMock()
    mock_options = MagicMock()
    mock_filter = MagicMock()
    mock_first = MagicMock()

    # Set the return_value attribute for each intermediate MagicMock object
    monkeypatch.setattr(database_client.Session.return_value.__enter__.return_value, "query", mock_query)
    monkeypatch.setattr(mock_query.return_value, "options", mock_options)
    monkeypatch.setattr(mock_options.return_value, "filter", mock_filter)
    monkeypatch.setattr(mock_filter.return_value, "first", mock_first)

    # Create a dictionary to represent the return value of session.query.first()
    _data = MagicMock(password="", is_active=True, employee_id=-1, company=MagicMock(company_id=-1), role=MagicMock(role_id=-1), create_date=datetime.datetime.now()) 
    mock_first.return_value = _data

    # patch >= <= for NFace logs
    nfl_mock = MagicMock(create_date=MagicMock())
    nfl_mock.create_date.__le__.return_value=True
    nfl_mock.create_date.__ge__.return_value=False
    monkeypatch.setattr("app.api.api.NFaceLogs", nfl_mock)

    # Patch model_validate and model_dump methods
    mock_employee_processed = {
        "password": "",
        "is_active": True,
        "employee_id": -1,
        "company": {"company_id": -1},
        "role": {"role_id": -1}
    } 

    mocked_formatter = MagicMock()
    mocked_dumper = MagicMock()
    mocked_dumper.model_dump.return_value = mock_employee_processed
    mocked_formatter.model_validate.return_value = mocked_dumper

    monkeypatch.setattr("app.api.api.InstitutionMF", mocked_formatter)


    # Make a request with valid credentials
    data= {}
    headers = {
        "x-access-token":"abc",
    }
    response = client_fixture.delete(f"{base_url}/institution/abc", headers=headers)

    # Assert response
    assert response.status_code == expected_response_status_code

