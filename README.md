# Todo-FastAPI

This Todo application, built with FastAPI, SQLAlchemy, pytest, Alembic, PostgreSQL, and Docker, offers an easy way to manage tasks for different users with role-based authentication. It provides RESTful endpoints to create, update, and organize tasks while supporting multiple user roles, ensuring secure and streamlined task management for teams.

## Getting Started

### Prerequisites

- [Docker](https://www.docker.com/get-started)
- [Docker Compose](https://docs.docker.com/compose/install/)
- [Python 3.12](https://www.python.org/downloads/)

### Running the API

- Clone this repository
  
```sh
cd fastapi-todo-app
docker-compose up -d
```

- Access [localhost](http://localhost/docs#/) for the swagger docs
- Create an user and start adding, removing, updating and deleting tasks
