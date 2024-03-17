#############
## Imports ##
#############

import os
import uuid
import time
import secrets

from fastapi import FastAPI, Request, Depends, status
from fastapi.responses import ORJSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.openapi.docs import get_redoc_html

from app.logger import Rotolog
from app.config import Settings

from app.utils.clients import DatabaseClient, EmailClient, OtpClient, RedisClient, CryptographyClient

##############################
## Initialize config object ##
##############################

config = Settings()

##################
## Logger Setup ##
##################

# Create Logs Directory If It Does Not Exist
if not os.path.exists(os.path.dirname(config.log_file)):
    os.makedirs(os.path.dirname(config.log_file))

# Initialize logger object
logger = Rotolog(
    log_file_name=config.log_file,
    log_format=config.log_format,
    max_log_files=config.log_backup_count,
    max_log_file_size=config.log_max_bytes,
    log_level=config.log_level
)

logger.info("Application Started")


###################
## Clients Setup ##
###################

# Setup DatabaseClient
database_client = DatabaseClient(db_username=config.db_username.get_secret_value(),db_password=config.db_password.get_secret_value(),db_host=config.db_host,db_name=config.db_name,db_port=config.db_port,db_type=config.db_type)
logger.debug(f"Setup DatabaseClient {database_client}")

# Setup RedisClient
redis_client = RedisClient(host=config.redis_host,port=config.redis_port,password=config.redis_password.get_secret_value())
logger.debug(f"Setup RedisClient {redis_client}")

# Setup EmailClient
email_client = EmailClient(email_sender=config.email_sender,email_password=config.email_password.get_secret_value())
logger.debug(f"Setup EmailClient {email_client}")

# Setup OtpClient
otp_client = OtpClient()
logger.debug(f"Setup OtpClient {otp_client}")



###################
## FastAPI SetUp ##
###################


# Initialize FastAPI Object
app = FastAPI(
    title=config.app_name,
    version=config.app_version,
    contact={
        "name": config.app_contact_name,
        "email": config.app_contact_email,
    },
    default_response_class=ORJSONResponse,
    docs_url=None,
    redoc_url=None
)

logger.debug("FastAPI Object Initialized")



###############################
## Request Logger Middleware ##
###############################

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    session_code = str(uuid.uuid4())

    # Log the request received, including headers and body
    logger.info(f"[{session_code}] Received - Client Host:{request.client.host} Request:{request.method} {request.url.path} Headers:{request.headers}")

    request.state.session_code = session_code
    response = await call_next(request)
    execution_time = time.time() - start_time
    # Log response
    logger.info(f"[{session_code}] Sent - Client Host:{request.client.host} Request:{request.method} {request.url.path} Status Code:{response.status_code} Execution Time:{execution_time}")    
    return response



################
## CORS Setup ##
################


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
logger.debug("Added CORS middleware")


################
## Setup APIs ##
################

# Ping endoint
@app.get("/ping", include_in_schema=False)
async def ping():
    return ORJSONResponse(status_code=status.HTTP_200_OK,content={"success":True,"version":config.app_version,"debug_message":"1"})


# Add router to main FastAPI app
from app.api.api import api as app_api
app.include_router(app_api, prefix="/nface/portal/api")
logger.debug("Added Router to main Fast API app")


#######################
## Docs API Endpoint ##
#######################

# Create basic auth dependancy
security = HTTPBasic()

# API for docs
@app.get("/redoc", include_in_schema=False)
async def get_redoc_documentation(credentials: HTTPBasicCredentials = Depends(security)):
    # Retrieve username and password
    correct_username = secrets.compare_digest(credentials.username, config.app_docs_basic_username)
    correct_password = secrets.compare_digest(credentials.password, config.app_docs_basic_password.get_secret_value())
    # Validate username and password
    if not (correct_username and correct_password):
        logger.debug("Failed to login to docs page")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    logger.debug("Successfully logged in to docs page")
    return get_redoc_html(openapi_url="/openapi.json", title=f"{config.app_name} Documentation")


############################
## API Exception Handlers ##
############################

from app.utils.schema import BaseResponse, BaseMeta, BaseError

# Exception Handler that overrides default RequestValidationError
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Log the error in log file
    _error = str(exc.with_traceback(None))
    logger.error(f"{_error}")
    # Get session code
    session_code = str(uuid.uuid4())

    # Create responsee content
    _content = BaseResponse(
        meta=BaseMeta(
            successful=False,
            _id=session_code,
            message=None
        ),
        data=None,
        error=BaseError(
            error_message="bad request"
        )
    )
    return ORJSONResponse( status_code=status.HTTP_400_BAD_REQUEST, content=_content.model_dump(),)


# Exception handler to deal with unexpected errors
@app.exception_handler(status.HTTP_500_INTERNAL_SERVER_ERROR)
async def unicorn_exception_handler(request: Request, exc: Exception):    
    # Log the error in log file
    _error = str(exc.with_traceback(None))
    # log error
    logger.error(f"{_error}")
    # Get session code
    session_code = request.state.session_code

    # Create responsee content
    _content = BaseResponse(
        meta=BaseMeta(
            _id=session_code,
            successful=False,
            message=None
        ),
        data=None,
        error=BaseError(
            error_message="internal server error"
        )
    )
    return ORJSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content= _content.model_dump(), )