import pickle
from abc import ABC, abstractmethod
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKeyWithSerialization, RSAPublicKey
from .exception import AuthenticationError
from uuid import UUID

from .constants import (
    HASHING_ALGORITHM,
    HEADING_BYTEORDER,
    HEADING_LENGTH,
    HEADING_SIGNED,
    KEY_ALGORITHM,
    KEY_MGF,
    KEY_MGF_ALGORITHM,
    KEY_PADDING,
    ZERO_UUID,
)


from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from cryptography.hazmat.primitives import serialization


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
    def __init__(self, message: bytes, data: object):
        self.bytes = message
        self.data = data

    @classmethod
    def from_bytes(cls, message: bytes):
        cls(message, pickle.loads(message))


class Request:
    def __init__(self, command: Command, message: Message):
        self.command = command
        self.message = message


class Cryption(ABC):
    def __init__(self, uuid: UUID, secret_uuid: UUID):
        self._uuid = uuid
        self._secret_uuid = secret_uuid

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """
            Encrypts message
        """

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        """
            Decrypts message
        """

    def unarchive(self, decrypted_message: bytes) -> object:
        client_secret_uuid = decrypted_message[:16]
        if client_secret_uuid != self._secret_uuid.bytes:
            raise AuthenticationError("Wrong secret key.")
        return pickle.loads(decrypted_message[16:])

    def archive(self, data: object) -> bytes:
        return self._secret_uuid.bytes + pickle.dumps(data)

    def prepare_response(self, encrypted_message: bytes) -> bytes:
        data = self._uuid.bytes + encrypted_message
        data_length = len(data)
        heading = data_length.to_bytes(
            HEADING_LENGTH, byteorder=HEADING_BYTEORDER, signed=HEADING_SIGNED
        )
        return heading + data

    def get_request(self, encrypted_message: bytes) -> bytes:
        uuid = encrypted_message[0:16]
        if uuid != self._uuid.bytes:
            raise AuthenticationError("Wrong uuid.")
        return encrypted_message[16:]

    def encrypt_and_prepare(self, request: Request) -> bytes:
        message_datagram = (request.command, request.message.bytes)
        archived_datagram = self.archive(message_datagram)
        encrypted_message = self.encrypt(archived_datagram)
        return self.prepare_response(encrypted_message)

    def get_request_and_decrypt(self, encrypted_request: bytes) -> Request:
        encrypted_message = self.get_request(encrypted_request)
        decrypted_message = self.decrypt(encrypted_message)
        command, message = self.unarchive(decrypted_message)
        return Request(command, Message.from_bytes(message))


class IdentCryption(Cryption):
    def __init__(self):
        super().__init__(ZERO_UUID, ZERO_UUID)

    def encrypt(self, data: bytes) -> bytes:
        return data

    def decrypt(self, data: bytes) -> bytes:
        return data


class FernetCryption(Cryption):
    def __init__(self, uuid: UUID, secret_uuid: UUID, sym_key: bytes):
        super().__init__(uuid, secret_uuid)
        self._cryption = Fernet(sym_key)

    def decrypt(self, data: bytes) -> bytes:
        return self._cryption.decrypt(data)

    def encrypt(self, data: bytes) -> bytes:
        return self._cryption.encrypt(data)


class RSAEncryption(Cryption):
    def __init__(self, uuid: UUID, secret_uuid: UUID, public_key: bytes):
        super().__init__(uuid, secret_uuid)
        self._public_key: RSAPublicKey = public_key

    def encrypt(self, data: bytes) -> bytes:
        return self._public_key.encrypt(
            data,
            KEY_PADDING(
                mgf=KEY_MGF(algorithm=KEY_MGF_ALGORITHM()),
                algorithm=KEY_ALGORITHM(),
                label=None,
            ),
        )

    def decrypt(self, data: bytes) -> bytes:
        return NotImplemented


class RSADecryption(Cryption):
    def __init__(self, uuid: UUID, secret_uuid: UUID, private_key: bytes):
        super().__init__(uuid, secret_uuid)
        self._private_key: RSAPrivateKeyWithSerialization = private_key

    def encrypt(self, data: bytes) -> bytes:
        return NotImplemented

    def decrypt(self, data: bytes) -> bytes:
        return self._private_key.decrypt(
            data,
            KEY_PADDING(
                mgf=KEY_MGF(algorithm=KEY_MGF_ALGORITHM()),
                algorithm=KEY_ALGORITHM(),
                label=None,
            ),
        )
