#############
## Imports ##
#############

import inspect
import logging
from logging.handlers import RotatingFileHandler


######################
## Class Definition ##
######################

class Rotolog:

    # Initialize the class
    def __init__(self, log_file_name:str, log_format:str, max_log_files:int=5, max_log_file_size:int=1024*1024, log_level:int=logging.DEBUG) -> None:
        
        # Full path of the log file
        self.log_file_name = log_file_name
        # Format of the Log messages
        self.log_format = log_format 
        # Maximum number of log files that will be created
        self.max_log_files = max_log_files
        # Maximum size of a single log file
        self.max_log_file_size = max_log_file_size
        # Level of the logs that will be logged eg. DEBUG, INFO, ERROR etc
        self.log_level = log_level

        # Setup Logger
        self.setup_logger()
 
    def setup_logger(self) -> None:
        # Create a logger with the specified log level
        self.logger = logging.getLogger(self.log_file_name)
        self.logger.setLevel(self.log_level)
 
        # Create a rotating file handler with the specified max log file size and max log files
        file_handler = RotatingFileHandler(
            self.log_file_name,
            maxBytes=self.max_log_file_size,
            backupCount=self.max_log_files
        )
 
        # Create a formatter and attach it to the file handler
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s')
        file_handler.setFormatter(formatter)
 
        # Add the file handler to the logger
        self.logger.addHandler(file_handler)

    def debug(self, message:str) -> None:
        # Log a debug message
        self.logger.debug(message)

    def info(self, message:str) -> None:
        # Log an info message
        self.logger.info(message)
    
    def error(self, message:str) -> None:
        # Get calling function name
        calling_function = inspect.currentframe().f_back.f_code.co_name
        # Log an error message
        self.logger.error(f"[{calling_function}]-{message}")
