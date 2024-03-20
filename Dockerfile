FROM python:3.8-slim-buster

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
  && apt-get install -y --no-install-recommends curl gcc g++ gnupg unixodbc-dev \
  && apt-get clean

# Add SQL Server ODBC Driver 17 for Ubuntu 18.04
RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - \
  && curl https://packages.microsoft.com/config/debian/10/prod.list > /etc/apt/sources.list.d/mssql-release.list \
  && apt-get update \
  && apt-get install -y --no-install-recommends --allow-unauthenticated msodbcsql17 mssql-tools \
  && echo 'export PATH="$PATH:/opt/mssql-tools/bin"' >> ~/.bash_profile \
  && echo 'export PATH="$PATH:/opt/mssql-tools/bin"' >> ~/.bashrc \
  && apt-get clean

# Set work directory
WORKDIR /home/calcot/nface

# Copy requirements and install Python packages
COPY requirements.txt requirements.txt
RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && rm -rf /root/.cache/pip/*

# Copy the application code
COPY app app
COPY logs logs
COPY run.py run.py

# Expose port
EXPOSE 8000

# Set the default command to run the application
CMD ["python", "run.py"]
