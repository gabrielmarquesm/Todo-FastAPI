# Todo-FastAPI

This is a Todo application built with FastAPI, pytest, Alembic, PostgreSQL, and Docker. The application provides RESTful endpoints to manage todos and users associated with them.

## Table of Contents
- [Todo-FastAPI](#todo-fastapi)
  - [Table of Contents](#table-of-contents)
  - [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Running the API](#running-the-api)

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