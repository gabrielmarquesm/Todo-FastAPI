from fastapi import status

from ..routers.users import get_current_user, get_db
from .utils import app, client, override_get_current_user, override_get_db, test_user

app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_current_user] = override_get_current_user


def test_return_user(test_user):
    response = client.get("/user")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["username"] == "john_doe"
    assert response.json()["email"] == "john_doe@email.com"
    assert response.json()["first_name"] == "John"
    assert response.json()["last_name"] == "Doe"
    assert response.json()["role"] == "admin"


def test_change_password_success(test_user):
    response = client.put(
        "/user/password",
        json={"password": "test_password", "new_password": "new_password"},
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT


def test_change_password_invalid_current_password(test_user):
    response = client.put(
        "/user/password",
        json={"password": "wrong_password", "new_password": "new_password"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == {"detail": "Error on password change"}


def test_change_phone_number_success(test_user):
    response = client.put("/user/phonenumber/99999999")
    assert response.status_code == status.HTTP_204_NO_CONTENT
