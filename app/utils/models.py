#############
## Imports ##
#############

from sqlalchemy import MetaData
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy_serializer import SerializerMixin

from app import database_client


metadata = MetaData()
metadata.reflect(bind=database_client.engine)
Base = declarative_base()



class CurrencyMaster(Base,SerializerMixin):
    __table__ = metadata.tables['Currency_Master']
class StatusMaster(Base,SerializerMixin):
    __table__ = metadata.tables['Status_Master']
class ServiceMaster(Base,SerializerMixin):
    __table__ = metadata.tables['Service_Master']
class BankTypeMaster(Base,SerializerMixin):
    __table__ = metadata.tables['Bank_Type_Master']



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
    # __table_args__ = (UniqueConstraint('company_id', 'role_name', name='_company_role_uc'),)



class Employee(Base,SerializerMixin):
    __table__ = metadata.tables['Employee']
    role = relationship("Roles",)
    company = relationship("Company",)


class NFaceLogs(Base,SerializerMixin):
    __table__ = metadata.tables["Nface_Logs"]
    company = relationship("Company")
    status = relationship("StatusMaster")
    service = relationship("ServiceMaster")


class Invoice(Base,SerializerMixin):
    __table__ = metadata.tables["Invoice"]
    company = relationship("Company")


class CompanyBankingInfo(Base,SerializerMixin):
    __table__ = metadata.tables["Company_Banking_Info"]
    # company = relationship("Company")
    bank_type = relationship("BankTypeMaster")
    __mapper_args__ = { 'primary_key': [metadata.tables["Company_Banking_Info"].c.company_id] }
