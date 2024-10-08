from fastapi import HTTPException, status

from ..error_messages import ErrorMessages
from ..routers.todos import get_current_user, get_db
from .utils import (
    TestingSessionLocal,
    Todos,
    app,
    client,
    override_get_current_user,
    override_get_db,
    test_todo,
    test_user,
)

app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_current_user] = override_get_current_user


def test_read_all_authenticated(test_user, test_todo):
    response = client.get("/todos")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == [
        {
            "id": 1,
            "title": "Learn to code",
            "description": "Need to learn everyday",
            "priority": 5,
            "complete": False,
            "owner_id": 1,
        }
    ]


def test_read_one_authenticated(test_user, test_todo):
    response = client.get("/todos/todo/1")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {
        "id": 1,
        "title": "Learn to code",
        "description": "Need to learn everyday",
        "priority": 5,
        "complete": False,
        "owner_id": 1,
    }


def test_read_one_authenticated_not_found(test_user, test_todo):
    response = client.get("/todos/todo/999")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": ErrorMessages.TODO_NOT_FOUND}


def test_create_todo(test_user, test_todo):
    request_data = {
        "title": "New Todo",
        "description": "New todo description",
        "priority": 5,
        "complete": False,
    }

    response = client.post("/todos/todo/", json=request_data)
    assert response.status_code == status.HTTP_201_CREATED

    db = TestingSessionLocal()
    todo_model = db.query(Todos).filter(Todos.id == 2).first()

    assert todo_model is not None
    assert todo_model.title == request_data.get("title")
    assert todo_model.description == request_data.get("description")
    assert todo_model.priority == request_data.get("priority")
    assert todo_model.complete == request_data.get("complete")


def test_update_todo(test_user, test_todo):
    request_data = {
        "title": "New Todo Update",
        "description": "New todo description Update",
        "priority": 3,
        "complete": True,
    }

    response = client.put("/todos/todo/1", json=request_data)
    assert response.status_code == status.HTTP_204_NO_CONTENT
    db = TestingSessionLocal()
    todo_model = db.query(Todos).filter(Todos.id == 1).first()

    assert todo_model is not None
    assert todo_model.title == request_data.get("title")
    assert todo_model.description == request_data.get("description")
    assert todo_model.priority == request_data.get("priority")
    assert todo_model.complete == request_data.get("complete")


def test_update_todo_not_found(test_user, test_todo):
    request_data = {
        "title": "New Todo Update",
        "description": "New todo description Update",
        "priority": 3,
        "complete": True,
    }
    response = client.get("/todos/todo/999")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": ErrorMessages.TODO_NOT_FOUND}


def test_delete_todo(test_user, test_todo):
    response = client.delete("/todos/todo/1")
    assert response.status_code == status.HTTP_204_NO_CONTENT
    db = TestingSessionLocal()
    model = db.query(Todos).filter(Todos.id == 1).first()
    assert model is None


def test_delete_todo_not_found(test_user, test_todo):
    response = client.delete("/todos/todo/999")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": ErrorMessages.TODO_NOT_FOUND}
