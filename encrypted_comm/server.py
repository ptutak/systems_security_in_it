import logging
import socketserver
import threading
import uuid
from typing import Callable, Dict, List, Optional, Tuple

from cryptography.fernet import Fernet

from .common import (
    AsymmetricEncryption,
    Command,
    Cryption,
    FernetCryption,
    IdentCryption,
    Message,
    Request,
    RequestReceiver,
    Response,
    RSAEncryption,
)
from .constants import HASHING_ALGORITHM
from .exception import (
    InvalidCommand,
    RegistrationError,
    ResponseAddressError,
    ShasumError,
)


class ClientConnection:
    ZERO_CRYPTION = IdentCryption()

    def __init__(self, client_uuid: uuid.UUID, register_request: bytes):
        self._lock = threading.Lock()
        secret_uuid = uuid.uuid4()
        self._symmetric_key: bytes = Fernet.generate_key()
        self._cryption: Cryption = FernetCryption(
            client_uuid, secret_uuid, self._symmetric_key
        )

        self._client_communication_address = None
        request = self.ZERO_CRYPTION.decrypt_and_get_request(register_request)
        command, public_key_composit = request.command_or_response, request.message.data
        if command != Command.CONNECT:
            raise InvalidCommand("Expected CONNECT command.")

        public_key, public_key_sha256 = public_key_composit
        if HASHING_ALGORITHM(public_key).hexdigest() != public_key_sha256:
            raise ShasumError("The public key has been tampered.")

        encryption = RSAEncryption.from_serialized_key(public_key)

        self._public_key_cryption: AsymmetricEncryption = AsymmetricEncryption(
            client_uuid, secret_uuid, encryption
        )

    @property
    def communication_address(self):
        if self._client_communication_address is not None:
            return self._client_communication_address
        else:
            raise ResponseAddressError("The response address is not set.")

    @communication_address.setter
    def communication_address(self, communication_address: Tuple[str, int]):
        with self._lock:
            if self._client_communication_address is None:
                self._client_communication_address = communication_address
            else:
                raise ResponseAddressError(
                    "The response address for the connection is already set."
                )

    def prepare_encrypted_symmetric_key(self) -> bytes:
        symmetric_key_hash = HASHING_ALGORITHM(self._symmetric_key).hexdigest()
        data = (self._symmetric_key, symmetric_key_hash)
        request = Request(Response.CONNECTION_SUCCESS, Message.from_data(data))
        return self._public_key_cryption.prepare_request_and_encrypt(request)

    def decrypt(self, encrypted_request: bytes) -> Request:
        return self._cryption.decrypt_and_get_request(encrypted_request)

    def encrypt(self, request: Request) -> bytes:
        return self._cryption.prepare_request_and_encrypt(request)


class ClientRequest:
    def __init__(self, request: Request, connection: ClientConnection):
        self.request = request
        self.connection = connection


class ClientStorage:
    def __init__(self):
        self._clients_lock = threading.Lock()
        self._clients: Dict[bytes, ClientConnection] = {}

    def get_client_request(self, message: bytes) -> ClientRequest:
        with self._clients_lock:
            connection = self.match_client(message)
            if connection is None:
                new_connection = self._create_client(message)
                return ClientRequest(
                    Request(Command.CONNECT, Message.zero_message()), new_connection,
                )
            return ClientRequest(connection.decrypt(message), connection)

    def _create_client(self, message: bytes) -> ClientConnection:
        while True:
            new_uuid = uuid.uuid4()
            if new_uuid.bytes not in self._clients:
                break
        new_connection = ClientConnection(new_uuid, message)
        self._clients[new_uuid.bytes] = new_connection
        return new_connection

    def match_client(self, message: bytes) -> Optional[ClientConnection]:
        return self._clients.get(message[0:16])


class UserStorage:
    def __init__(self):
        self._lock = threading.Lock()
        self._client_nicknames: Dict[str, ClientConnection] = {}

    def get_client(self, nickname: str) -> Optional[ClientConnection]:
        return self._client_nicknames.get(nickname, None)

    def get_user_list(self) -> List[str]:
        return list(self._client_nicknames.keys())

    def register(self, nickname, client: ClientConnection) -> None:
        with self._lock:
            if self._client_nicknames.get(nickname) is not None:
                raise RegistrationError("Nickname already registered.")
            self._client_nicknames[nickname] = client


class EncryptionMessageHandler(socketserver.BaseRequestHandler, RequestReceiver):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self.logger = logging.getLogger(f"{__name__}[EncryptionMessageHandler]")

    def setup(self):
        pass

    def handle(self):
        heading, data = self.receive_data(self.request)
        client_request: ClientRequest = self.server.client_storage.get_client_request(
            data
        )
        if client_request.request.command_or_response in self.COMMANDS:
            self.COMMANDS[client_request.request.command_or_response](
                self, client_request
            )

    def _connect_command(self, client_request: ClientRequest,) -> None:
        encrypted_request = client_request.connection.prepare_encrypted_symmetric_key()
        self.request.sendall(encrypted_request)

    def _register_command(self, client_request: ClientRequest,) -> None:
        client_response_address, client_nickname = client_request.request.message.data
        host = self.client_address[0]
        port = client_response_address[1]
        client_request.connection.client_response_address = (host, port)

        try:
            self.server.user_storage.register(
                client_nickname, client_request.connection
            )
        except RegistrationError:
            encrypted_message = client_request.connection.encrypt(
                Request(Response.NICKNAME_ALREADY_USED, Message.zero_message())
            )
        else:
            encrypted_message = client_request.connection.encrypt(
                Request(Response.NICKNAME_REGISTRATION_SUCCESS, Message.zero_message())
            )

        self.request.sendall(encrypted_message)

    def _get_user_list_command(self, client_request: ClientRequest,) -> None:
        user_list = self.server.user_storage.get_user_list()
        encrypted_message = client_request.connection.encrypt(
            Request(Response.USER_LIST, Message.from_data(user_list))
        )
        self.request.sendall(encrypted_message)

    def _send_message_command(self, client_request: ClientRequest) -> None:
        pass

    def _reset_command(self, client_request: ClientRequest) -> None:
        pass

    def finish(self):
        pass

    COMMANDS: Dict[Command, Callable] = {
        Command.CONNECT: _connect_command,
        Command.GET_USER_LIST: _get_user_list_command,
        Command.REGISTER: _register_command,
        Command.MESSAGE: _send_message_command,
        Command.RESET: _reset_command,
    }


class EncryptionMessageServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, handler_class=EncryptionMessageHandler):
        super().__init__(server_address, handler_class)
        self.logger = logging.getLogger(f"{__name__}[EncryptionMessageServer]")
        self.client_storage = ClientStorage()
        self.user_storage = UserStorage()
