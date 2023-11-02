from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import MetaData
from sqlalchemy.orm import relationship, declarative_base

from sqlalchemy_serializer import SerializerMixin



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
        self.engine = create_engine(self.connection_string)
        self.Session = sessionmaker(bind=self.engine)


    def close_connection(self):
        self.session.close()
        self.engine.dispose()


db_username="admin"
db_password="QdWeYEk7xD2"
db_host="calcot-faceproof-mysql-db.c2pyeebkcdqx.eu-west-2.rds.amazonaws.com"
db_name="NFACE_DB_TEST"
db_port= "3306"
db_type='mysql'

database_client = DatabaseClient(db_username=db_username,db_password=db_password,db_host=db_host,db_name=db_name,db_port=db_port,db_type=db_type)


metadata = MetaData()
metadata.reflect(bind=database_client.engine)
Base = declarative_base()



class CurrencyMaster(Base,SerializerMixin):
    __table__ = metadata.tables['Currency_Master']

class StatusMaster(Base,SerializerMixin):
    __table__ = metadata.tables['Status_Master']

class ServiceMaster(Base,SerializerMixin):
    __table__ = metadata.tables['Service_Master']



class BillingFrequencyMaster(Base,SerializerMixin):
    __table__ = metadata.tables['Billing_Frequency_Master']


class BillingInformation(Base,SerializerMixin):
    __table__ = metadata.tables['Billing_Information']
    currency = relationship("CurrencyMaster")
    billing_frequency = relationship("BillingFrequencyMaster")

class Company(Base,SerializerMixin):
    __table__ = metadata.tables['Company']
    billing_information = relationship("BillingInformation")

class Roles(Base,SerializerMixin):
    __table__ = metadata.tables['Roles']
    company = relationship("Company")
    # __table_args__ = (UniqueConstraint('company_id', 'role_name', name='_company_role_uc'),)



class Employee(Base,SerializerMixin):
    __table__ = metadata.tables['Employee']
    role = relationship("Roles")
    company = relationship("Company")


class NFaceLogs(Base,SerializerMixin):
    __table__ = metadata.tables["NFace_Logs"]
    company = relationship("Company")
    status = relationship("StatusMaster")
    service = relationship("ServiceMaster")
    __mapper_args__ = { 'primary_key': [metadata.tables["NFace_Logs"].c.public_id] }


class Invoice(Base,SerializerMixin):
    __table__ = metadata.tables["Invoice"]
    company = relationship("Company")


class CompanyBankingInfo(Base,SerializerMixin):
    __table__ = metadata.tables["Company_Banking_Info"]
    company = relationship("Company")
    __mapper_args__ = { 'primary_key': [metadata.tables["Company_Banking_Info"].c.company_id] }
