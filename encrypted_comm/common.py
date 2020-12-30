from abc import ABC, abstractmethod
from enum import Enum
from uuid import UUID

from cryptography.fernet import Fernet


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
    @abstractmethod
    def encrypt(self, message: bytes) -> bytes:
        """
            Encrypts message
        """

    @abstractmethod
    def decrypt(self, message: bytes) -> bytes:
        """
            Decrypts message
        """

    @abstractmethod
    def prepare_response(self, message: bytes) -> bytes:
        """
            Prepares response
        """

    @abstractmethod
    def encrypt_and_prepare(self, message: Request) -> bytes:
        """
        """

    @abstractmethod
    def get_request_and_decrypt(self, request: bytes) -> Request:
        """
        """


class IdentCryption(Cryption):
    def __init__(self, uuid: UUID, secret_uuid: UUID):
        self._uuid = uuid
        self._secret_uuid = secret_uuid

    def encrypt(self, data: bytes) -> bytes:
        return data

    def decrypt(self, data: bytes) -> bytes:
        return data

    def prepare_response(self, message: bytes) -> bytes:
        return super().prepare_response(message)

    def get_request_and_decrypt(self, request: bytes) -> Request:
        return super().get_request_and_decrypt(request)

    def encrypt_and_prepare(self, message: Request) -> bytes:
        return super().encrypt_and_prepare(message)


class FernetCryption(Cryption):
    def __init__(self, uuid: UUID, secret_uuid: UUID, sym_key: bytes):
        self._uuid = uuid
        self._secret_uuid = secret_uuid
        self._cryption = Fernet(sym_key)

    def encrypt(self, data: bytes) -> bytes:
        pass

    def decrypt(self, data: bytes) -> bytes:
        pass

    def prepare_response(self, message: bytes) -> bytes:
        return super().prepare_response(message)

    def get_request_and_decrypt(self, request: bytes) -> Request:
        return super().get_request_and_decrypt(request)

    def encrypt_and_prepare(self, message: Request) -> bytes:
        return super().encrypt_and_prepare(message)
