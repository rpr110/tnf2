FROM python:3.8-slim-buster
#FROM python:3.11


# build variables.
ENV DEBIAN_FRONTEND noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1-mesa-glx \
    libglib2.0-0 \
    libsm6 \
    libxrender1 \
    libxext6 \
    && rm -rf /var/lib/apt/lists/*

# Install required dependencies, including pkg-config
RUN apt-get update && \
    apt-get install -y pkg-config libmariadb-dev

# install Microsoft SQL Server requirements.
ENV ACCEPT_EULA=Y
RUN apt-get update -y && apt-get update \
  && apt-get install -y --no-install-recommends curl gcc g++ gnupg unixodbc-dev

# Add SQL Server ODBC Driver 17 for Ubuntu 18.04
RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - \
  && curl https://packages.microsoft.com/config/debian/10/prod.list > /etc/apt/sources.list.d/mssql-release.list \
  && apt-get update \
  && apt-get install -y --no-install-recommends --allow-unauthenticated msodbcsql17 mssql-tools \
  && echo 'export PATH="$PATH:/opt/mssql-tools/bin"' >> ~/.bash_profile \
  && echo 'export PATH="$PATH:/opt/mssql-tools/bin"' >> ~/.bashrc

# clean the install.
RUN apt-get -y clean

WORKDIR /home/calcot/nface

COPY requirements.txt requirements.txt
# upgrade pip and install requirements.
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

COPY app app
COPY logs logs
COPY run.py run.py
EXPOSE 8000

CMD ["python","run.py"]
# CMD ["gunicorn", "run:app", "-w", "3", "--worker-class", "uvicorn.workers.UvicornWorker", "-b", "0.0.0.0:8000","--timeout","600"]