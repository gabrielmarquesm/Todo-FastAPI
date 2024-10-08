from datetime import timedelta

import jwt
import pytest
from fastapi import HTTPException, status

from ..config import settings
from ..error_messages import ErrorMessages
from ..routers.auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    get_db,
)
from .utils import TestingSessionLocal, app, override_get_db, test_user

app.dependency_overrides[get_db] = override_get_db


def test_authenticate_user(test_user):
    db = TestingSessionLocal()

    authenticated_user = authenticate_user(test_user.username, "test_password", db)
    assert authenticated_user is not False
    assert authenticated_user.username == test_user.username

    non_existent_user = authenticate_user("wrong_username", "wrong_password", db)
    assert non_existent_user is False

    wrong_password_user = authenticate_user(test_user.username, "wrong_password", db)
    assert wrong_password_user is False


def test_create_access_token():
    username = "testuser"
    user_id = 1
    role = "user"
    expires_delta = timedelta(days=1)

    token = create_access_token(username, user_id, role, expires_delta)

    decoded_token = jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        options={"verify_signature": False},
    )

    assert decoded_token["sub"] == username
    assert decoded_token["id"] == user_id
    assert decoded_token["role"] == role


@pytest.mark.asyncio
async def test_get_current_user_valid_token():
    encode = {"sub": "testuser", "id": 1, "role": "admin"}
    token = jwt.encode(encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

    user = await get_current_user(token=token)
    assert user == {"username": "testuser", "id": 1, "user_role": "admin"}


@pytest.mark.asyncio
async def test_get_current_user_missing_payload():
    encode = {"role": "user"}
    token = jwt.encode(encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

    with pytest.raises(HTTPException) as exception_info:
        await get_current_user(token=token)

    assert exception_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exception_info.value.detail == ErrorMessages.INVALID_USER
