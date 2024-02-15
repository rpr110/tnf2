#############
## Imports ##
#############

import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr


########################
## Define Config Class #
########################

class Settings(BaseSettings):

    # Location of .env File
    model_config = SettingsConfigDict(env_file=os.getenv("CONFIG_PATH"))

    # Environment Config
    env_type:str

    # Application Docs Config
    app_name:str
    app_version:str
    app_contact_name:str
    app_contact_email:str
    app_api_docs_description_path:str
    app_terms_of_service_link:str
    app_docs_basic_username:str
    app_docs_basic_password:SecretStr

    # NIBSS Config
    nibss_msauth_advised_url:str
    nibss_msauth_endpoint:str
    nibss_msauth_app_name:str

    # Database Config
    db_type:str
    db_username:SecretStr
    db_password:SecretStr
    db_host:str
    db_name:str
    db_port:int

    # Redis Config
    redis_host:str
    redis_password:SecretStr
    redis_port:int

    # Email Config
    email_sender:str
    email_password:SecretStr

    # Logging Config
    log_format:str
    log_file:str
    log_level:int
    log_mode:str
    log_max_bytes:int
    log_backup_count:int
    log_logger_name:str
