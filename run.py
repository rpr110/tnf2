#############
## Imports ##
#############

import uvicorn
from app import app


if __name__ == "__main__":

    # Run Application
    uvicorn.run(app, host="0.0.0.0", port=8000)