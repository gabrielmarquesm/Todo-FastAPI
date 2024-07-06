from fastapi import status

from ..routers.admin import get_current_user, get_db
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


def test_admin_read_all_authenticated(test_user, test_todo):
    response = client.get("/admin/todo")
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


def test_admin_delete_todo(test_user, test_todo):
    response = client.delete("/admin/todo/1")
    assert response.status_code == status.HTTP_204_NO_CONTENT

    db = TestingSessionLocal()
    model = db.query(Todos).filter(Todos.id == 1).first()
    assert model is None


def test_admin_delete_todo_not_found(test_user, test_todo):
    response = client.delete("/admin/todo/999")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "Todo not found"}
