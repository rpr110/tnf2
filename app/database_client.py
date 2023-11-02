#############
## Imports ##
#############

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

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