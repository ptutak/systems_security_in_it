from abc import ABC
from enum import Enum


class Command(Enum):
    CONNECT = "connect"
    REGISTER = "register"
    SEND_MESSAGE = "send_message"
    GET_USER_LIST = "get_user_list"
    RESET = "reset"


class Response(Enum):
    NICKNAME_ALREADY_USED = "nickname_already_used"
    NICKNAME_REGISTRATION_SUCCESS = "nickname_registration_success"
    USER_LIST = "user_list"


class Request:
    def __init__(self, raw_bytes):
        self._raw_bytes = raw_bytes


class Cryption(ABC):
    def encrypt(self, message: Request) -> bytes:
        """
            Encrypts message
        """

    def decrypt(self, message: bytes) -> Request:
        """
            Decrypts message
        """
