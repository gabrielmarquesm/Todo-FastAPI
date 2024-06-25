import os

from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
SQLALCHEMY_DATABASE_URL = os.getenv("SQLALCHEMY_DATABASE_URL")
SQLALCHEMY_TEST_DATABASE_URL = os.getenv("SQLALCHEMY_TEST_DATABASE_URL")
