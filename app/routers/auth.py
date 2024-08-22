from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Annotated

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, ValidationError
from sqlalchemy.orm import Session

from ..config import settings
from ..error_messages import ErrorMessages
from ..models import Users
from ..utils import get_db

router = APIRouter()

db_dependency = Annotated[Session, Depends(get_db)]
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")


class Role(str, Enum):
    ADMIN = "admin"
    USER = "user"


class CreateUserRequest(BaseModel):
    username: str
    email: str
    first_name: str
    last_name: str
    password: str
    role: Role
    phone_number: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenPayload(BaseModel):
    sub: str
    id: int
    role: str


def authenticate_user(username: str, password: str, db: db_dependency):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not bcrypt.checkpw(password.encode(), user.hashed_password.encode()):
        return False

    return user


def create_access_token(
    username: str, user_id: int, role: str, expires_delta: timedelta
):
    encode = {"sub": username, "id": user_id, "role": role}
    expires = datetime.now(UTC) + expires_delta
    encode.update({"exp": expires})
    return jwt.encode(encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM]
        )

        token_data = TokenPayload(**payload)

    except (jwt.InvalidTokenError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=ErrorMessages.INVALID_USER
        )

    return {
        "username": token_data.sub,
        "id": token_data.id,
        "user_role": token_data.role,
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, create_user_request: CreateUserRequest):
    password = create_user_request.password.encode()
    salt = bcrypt.gensalt()

    create_user_model = Users(
        email=create_user_request.email,
        username=create_user_request.username,
        first_name=create_user_request.first_name,
        last_name=create_user_request.last_name,
        hashed_password=bcrypt.hashpw(password, salt).decode(),
        is_active=True,
        role=create_user_request.role,
        phone_number=create_user_request.phone_number,
    )

    db.add(create_user_model)
    db.commit()


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency
):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ErrorMessages.INVALID_USER,
        )

    token = create_access_token(
        user.username, user.id, user.role, timedelta(minutes=settings.JWT_TTL)
    )
    return {"access_token": token, "token_type": "bearer"}
