FROM python:3.12
WORKDIR /code
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app/ /code/app