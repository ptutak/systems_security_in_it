from abc import ABC
from enum import Enum
from uuid import UUID

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


class Message:
    def __init__(self, message: bytes):
        self.bytes = message


class Request:
    def __init__(self, command: Command, message: Message):
        self.command = command
        self.message = message


class Cryption(ABC):
    def encrypt(self, message: bytes) -> bytes:
        """
            Encrypts message
        """

    def decrypt(self, message: bytes) -> bytes:
        """
            Decrypts message
        """
