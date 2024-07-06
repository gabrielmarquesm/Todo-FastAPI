from enum import Enum


class ErrorMessages(str, Enum):
    AUTHENTICATION_FAILED = "Authentication Failed"
    TODO_NOT_FOUND = "Todo not found"
    INVALID_USER = "Could not validate user"
    PASSWORD_CHANGE = "Error on password change"
