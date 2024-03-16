#############
## Imports ##
#############

from sqlalchemy import MetaData
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy_serializer import SerializerMixin

from app import database_client, config


metadata = MetaData()
metadata.reflect(bind=database_client.engine)
Base = declarative_base()

from unittest.mock import MagicMock
inheritance_metaclass_dict = {} if config.env_type!="unit-test" else {"metaclass":MagicMock()}

############
## Models ##
############



class CurrencyMaster(Base, SerializerMixin, **inheritance_metaclass_dict):
    __table__ = metadata.tables['Currency_Master']
class StatusMaster(Base, SerializerMixin, **inheritance_metaclass_dict):
    __table__ = metadata.tables['Status_Master']
class ServiceMaster(Base, SerializerMixin, **inheritance_metaclass_dict):
    __table__ = metadata.tables['Service_Master']
class BankTypeMaster(Base, SerializerMixin, **inheritance_metaclass_dict):
    __table__ = metadata.tables['Bank_Type_Master']
class BillingModeTypeMaster(Base, SerializerMixin, **inheritance_metaclass_dict):
    __table__ = metadata.tables['Billing_Mode_Type_Master']
class BillingFrequencyMaster(Base, SerializerMixin, **inheritance_metaclass_dict):
    __table__ = metadata.tables['Billing_Frequency_Master']
class VerificationCode(Base, SerializerMixin, **inheritance_metaclass_dict):
    __table__ = metadata.tables['Verification_Code']

class Wallet(Base, SerializerMixin, **inheritance_metaclass_dict):
    __table__ = metadata.tables["Wallet"]


class VolumeTariff(Base, SerializerMixin, **inheritance_metaclass_dict):
    __table__ = metadata.tables["Volume_Tariff"]


class Institution(Base, SerializerMixin, **inheritance_metaclass_dict):
    __table__ = metadata.tables['Institution']
    currency = relationship("CurrencyMaster")
    billing_frequency = relationship("BillingFrequencyMaster")
    billing_mode_type = relationship("BillingModeTypeMaster")
    volume_tariff = relationship("VolumeTariff")

class BillingInformation(Base, SerializerMixin, **inheritance_metaclass_dict):
    __table__ = metadata.tables['Billing_Information']
    currency = relationship("CurrencyMaster")
    billing_frequency = relationship("BillingFrequencyMaster")
    billing_mode_type = relationship("BillingModeTypeMaster")
    institution = relationship("Institution")
    volume_tariff = relationship("VolumeTariff")
    #company

class Company(Base, SerializerMixin, **inheritance_metaclass_dict):
    __table__ = metadata.tables['Company']
    billing_information = relationship("BillingInformation", uselist=False)
    banking_information = relationship("CompanyBankingInfo", uselist=False)
    wallet = relationship("Wallet",uselist=False)

class Roles(Base, SerializerMixin, **inheritance_metaclass_dict):
    __table__ = metadata.tables['Roles']
    # __table_args__ = (UniqueConstraint('company_id', 'role_name', name='_company_role_uc'),)



class Employee(Base, SerializerMixin, **inheritance_metaclass_dict):
    __table__ = metadata.tables['Employee']
    role = relationship("Roles",)
    company = relationship("Company",)


class NFaceLogs(Base, SerializerMixin, **inheritance_metaclass_dict):
    __table__ = metadata.tables["Nface_Logs"]
    company = relationship("Company")
    status = relationship("StatusMaster")
    service = relationship("ServiceMaster")


class Invoice(Base, SerializerMixin, **inheritance_metaclass_dict):
    __table__ = metadata.tables["Invoice"]
    company = relationship("Company")


class CompanyBankingInfo(Base, SerializerMixin, **inheritance_metaclass_dict):
    __table__ = metadata.tables["Company_Banking_Info"]
    # company = relationship("Company")
    bank_type = relationship("BankTypeMaster")
    __mapper_args__ = { 'primary_key': [metadata.tables["Company_Banking_Info"].c.company_id] }

