#############
## Imports ##
#############

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import secrets
import string 

import smtplib
import ssl
from email.message import EmailMessage

#####################
## Database Client ##
#####################


class DatabaseClient:


    @staticmethod
    def create_db_connection_string(db_username:str, db_password:str, db_host:str, db_name:str, db_port:int=None, db_type:str='mysql'):

        if db_type.lower() == 'mysql':
            db_port = db_port or '3306'
            return f"mysql://{db_username}:{db_password}@{db_host}:{db_port}/{db_name}"

        elif db_type.lower() == 'sqlserver':
            db_port = db_port or '1433'
            return f"mssql+pyodbc://{db_username}:{db_password}@{db_host}:{db_port}/{db_name}?driver=ODBC+Driver+17+for+SQL+Server"

        elif db_type.lower() == 'postgres':
            db_port = db_port or '5432'
            return f"postgresql://{db_username}:{db_password}@{db_host}:{db_port}/{db_name}"

        elif db_type.lower() == 'sqlite':
            return f"sqlite:///{db_name}"

        else:
            raise ValueError("Unsupported database type")
        

    def __init__(self, db_username:str, db_password:str, db_host:str, db_name:str, db_port:int, db_type:str) -> None:
        # Initialize db username
        self.db_username=db_username
        # Initialize db password
        self.db_password=db_password
        # Initialize db host
        self.db_host=db_host
        # Initialize db name
        self.db_name=db_name
        # Initialize db port
        self.db_port=db_port
        # Initialize db type
        self.db_type=db_type

        # Create connection string
        self.connection_string = DatabaseClient.create_db_connection_string(self.db_username, self.db_password, self.db_host, self.db_name, self.db_port, self.db_type)

        # Initialize ORM
        self.engine = create_engine(self.connection_string, pool_recycle=3600)
        self.Session = sessionmaker(bind=self.engine)


    def close_connection(self):
        self.session.close()
        self.engine.dispose()


##################
## Email Client ##
##################

class EmailClient:
    
    def __init__(self, email_sender, email_password) -> None:
        self.email_sender = email_sender
        self.email_password = email_password

    def send_mail(self, email_receiver:str, subject:str, body:str):
        em = EmailMessage()
        em['From'] = self.email_sender
        em['To'] = email_receiver
        em['Subject'] = subject
        em.set_content(body)

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(self.email_sender, self.email_password)
            smtp.sendmail(self.email_sender, email_receiver, em.as_string())


################
## OTP Client ##
################

class OtpClient:
    def __init__(self) -> None:
        # Initialize Characters
        self.characters = string.ascii_letters + string.digits

    def create_verification_code(self, code_length:int):
        # Create random verifictaion code
        verification_code = "".join(secrets.choice(self.characters) for _ in range(code_length))
        return verification_code
    
    def create_verification_code_session(self, db_session, db_table_obj, email_id, verification_code):

        # Check if email_id already has verifiction code
        verification_code_data = db_session.query(
            db_table_obj
        ).filter(
            db_table_obj.email_id  == email_id
        ).first()

        
        if verification_code_data:
            # If verification code exists, update to new verification code
            verification_code_data._code = verification_code
        else:
            # If verification code not exists, create new verification code
            new_verification_code = db_table_obj(email_id=email_id, _code=verification_code)
            db_session.add(new_verification_code)

        # Commit changes to DB
        db_session.commit()


###########################
## Data Formatter Client ##
###########################

class DataFormatterClient:

    def __init__(self) -> None:
        pass

    @staticmethod
    def remove_keys_from_dict(data:dict, keys_to_remove:list)->None:
        
        if not isinstance(data, dict):
            return

        for key in keys_to_remove:
            key_parts = key.split('.')
            current_data = data
            for part in key_parts[:-1]:
                current_data = current_data.get(part, {})
            last_key = key_parts[-1]
            if last_key in current_data:
                del current_data[last_key]

        for key, value in data.items():
            __class__.remove_keys_from_dict(value, keys_to_remove)

    @staticmethod
    def response_creator(response, meta, data, error, status_code, fastapi_response_class):
        _content = response(meta=meta, data=data, error=error)
        return fastapi_response_class(status_code=status_code, content=_content.model_dump())
    

