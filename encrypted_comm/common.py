import pickle
import socket
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional, Tuple, Union
from uuid import UUID

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import PublicFormat

from .constants import (
    HEADING_BYTEORDER,
    HEADING_LENGTH,
    HEADING_SIGNED,
    KEY_ALGORITHM,
    KEY_MGF,
    KEY_MGF_ALGORITHM,
    KEY_PADDING,
    KEY_SIZE,
    ZERO_UUID,
)
from .exception import AuthenticationError


class Command(Enum):
    CONNECT = "connect"
    REGISTER = "register"
    MESSAGE = "message"
    CONNECT_TO_USER = "connect_to_user"
    DISCONNECT_USER = "disconnect_user"
    GET_USER_LIST = "get_user_list"
    PING = "ping"


class Response(Enum):
    USER_LIST = "user_list"

    CONNECTION_SUCCESS = "connection_success"
    NICKNAME_REGISTRATION_SUCCESS = "nickname_registration_success"
    MESSAGE_SUCCESS = "message_success"
    DISCONNECTION_SUCCESS = "disconnection_success"

    CLIENT_NOT_REGISTERED = "client_not_registered"
    USER_NOT_REGISTERED = "user_not_registered"
    USER_NOT_CONNECTED = "user_not_connected"
    REGISTRATION_ERROR = "registration_error"
    WRONG_COMMAND = "wrong_command"
    ERROR = "error"


class Message:
    def __init__(self, data: object):
        self.data = data

    @property
    def bytes(self) -> bytes:
        return pickle.dumps(self.data)

    @classmethod
    def from_bytes(cls, message: bytes):
        return cls(pickle.loads(message))

    @classmethod
    def from_data(cls, data: object):
        return cls(data)

    @classmethod
    def zero_message(cls):
        return cls.from_data(tuple())

    def __repr__(self) -> str:
        return f"Message({self.data})"


class ChatMessage(Message):
    def __init__(self, sender: Optional[str], receiver: str, message: bytes):
        super().__init__((sender, receiver, message))

    @property
    def sender(self):
        return self.data[0]

    @sender.setter
    def sender(self, nickname: str):
        data = self.data
        self.data = (nickname, data[1], data[2])

    @property
    def receiver(self):
        return self.data[1]

    @property
    def message(self):
        return self.data[2]

    @classmethod
    def from_message(cls, message: Message) -> "ChatMessage":
        return cls(message.data[0], message.data[1], message.data[2])

    @classmethod
    def from_bytes(cls, message: bytes) -> "ChatMessage":
        return cls.from_message(super().from_bytes(message))

    @classmethod
    def from_data(cls, data: object) -> "ChatMessage":
        return cls.from_message(super().from_data(data))


class Request:
    def __init__(self, command_or_response: Union[Command, Response], message: Message):
        self.command_or_response = command_or_response
        self.message = message


class RSAEncryption:
    def __init__(self, public_key: rsa.RSAPublicKey):
        self._public_key = public_key

    @property
    def public_key_serialized(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )

    @classmethod
    def from_serialized_key(cls, public_key_serialized) -> "RSAEncryption":
        public_key: rsa.RSAPublicKey = serialization.load_pem_public_key(
            public_key_serialized, default_backend()
        )
        return RSAEncryption(public_key)

    def encrypt(self, data: bytes) -> bytes:
        return self._public_key.encrypt(
            data,
            KEY_PADDING(
                mgf=KEY_MGF(algorithm=KEY_MGF_ALGORITHM()),
                algorithm=KEY_ALGORITHM(),
                label=None,
            ),
        )


class RSADecryption:
    def __init__(self, private_key: rsa.RSAPrivateKeyWithSerialization):
        self._private_key = private_key

    def decrypt(self, data: bytes) -> bytes:
        return self._private_key.decrypt(
            data,
            KEY_PADDING(
                mgf=KEY_MGF(algorithm=KEY_MGF_ALGORITHM()),
                algorithm=KEY_ALGORITHM(),
                label=None,
            ),
        )


class RSACryption(RSAEncryption, RSADecryption):
    def __init__(self):
        self._private_key: rsa.RSAPrivateKeyWithSerialization = rsa.generate_private_key(
            public_exponent=65537, key_size=KEY_SIZE, backend=default_backend()
        )
        self._public_key: rsa.RSAPublicKey = self._private_key.public_key()


class Cryption(ABC):
    def __init__(self, uuid: UUID, secret_uuid: UUID):
        self._uuid = uuid
        self._secret_uuid = secret_uuid

    @property
    def uuid(self):
        return self._uuid

    @property
    def secret_uuid(self):
        return self._secret_uuid

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

    def get_request_bytes(self, encrypted_message: bytes) -> bytes:
        uuid = encrypted_message[0:16]
        if uuid != self.uuid.bytes:
            raise AuthenticationError("Wrong uuid.")
        return encrypted_message[16:]

    def archive(self, data: object) -> bytes:
        return self.secret_uuid.bytes + pickle.dumps(data)

    def prepare_response(self, encrypted_message: bytes) -> bytes:
        data = self._uuid.bytes + encrypted_message
        data_length = len(data)
        heading = data_length.to_bytes(
            HEADING_LENGTH, byteorder=HEADING_BYTEORDER, signed=HEADING_SIGNED
        )
        return heading + data

    def prepare_request_and_encrypt(self, request: Request) -> bytes:
        message_datagram = (request.command_or_response, request.message.bytes)
        archived_datagram = self.archive(message_datagram)
        encrypted_message = self.encrypt(archived_datagram)
        return self.prepare_response(encrypted_message)

    def decrypt_and_get_request(self, encrypted_request: bytes) -> Request:
        encrypted_message = self.get_request_bytes(encrypted_request)
        decrypted_message = self.decrypt(encrypted_message)
        command_or_response, message = self.unarchive(decrypted_message)
        return Request(command_or_response, Message.from_bytes(message))


class IdemCryption(Cryption):
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


class AsymmetricEncryption(Cryption):
    def __init__(self, uuid: UUID, secret_uuid: UUID, encryption: RSAEncryption):
        super().__init__(uuid, secret_uuid)
        self._encryption = encryption

    def encrypt(self, data: bytes) -> bytes:
        return self._encryption.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return NotImplemented


class AsymmetricDecryption(Cryption):
    def __init__(self, decryption: RSADecryption):
        super().__init__(ZERO_UUID, ZERO_UUID)
        self._decryption = decryption

    def decrypt(self, data: bytes) -> bytes:
        return self._decryption.decrypt(data)

    def encrypt(self, data: bytes) -> bytes:
        return NotImplemented

    def unarchive(self, decrypted_message: bytes) -> object:
        client_secret_uuid = decrypted_message[:16]
        self._secret_uuid = UUID(bytes=client_secret_uuid)
        return pickle.loads(decrypted_message[16:])

    def get_request_bytes(self, encrypted_message: bytes) -> bytes:
        uuid = encrypted_message[0:16]
        self._uuid = UUID(bytes=uuid)
        return encrypted_message[16:]


class ConnectionHandler:
    @classmethod
    def receive_data(cls, connection) -> Tuple[int, bytes]:
        heading = connection.recv(HEADING_LENGTH)
        data_length = int.from_bytes(
            heading, byteorder=HEADING_BYTEORDER, signed=HEADING_SIGNED,
        )
        data = connection.recv(data_length)
        return (data_length, data)

    @classmethod
    def send_data_and_receive_response(
        cls, encrypted_data: bytes, address: Tuple[str, int]
    ) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.connect(address)
            connection.sendall(encrypted_data)
            heading, data = cls.receive_data(connection)
            return data


class EncryptingConnectionHandler(ConnectionHandler, ABC):
    @property
    @abstractmethod
    def cryption(self) -> Cryption:
        """
        Cryption.
        """

    @property
    @abstractmethod
    def communication_address(self) -> Tuple[str, int]:
        """
        Address to send and receive requests.
        """

    def encrypt(self, request: Request) -> bytes:
        return self.cryption.prepare_request_and_encrypt(request)

    def decrypt(self, encrypted_response: bytes) -> Request:
        return self.cryption.decrypt_and_get_request(encrypted_response)

    def send_request(self, request: Request) -> Request:
        encrypted_request = self.encrypt(request)
        encrypted_response = self.send_data_and_receive_response(
            encrypted_request, self.communication_address
        )
        return self.decrypt(encrypted_response)
