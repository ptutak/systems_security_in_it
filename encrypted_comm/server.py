import logging
import socketserver
import threading
import uuid
from typing import Callable, Dict, List, Optional, Tuple

from cryptography.fernet import Fernet

from .common import (
    AsymmetricEncryption,
    ChatMessage,
    Command,
    Cryption,
    EncryptingConnectionHandler,
    FernetCryption,
    IdemCryption,
    Message,
    Request,
    ConnectionHandler,
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


class ClientConnection(EncryptingConnectionHandler):
    ZERO_CRYPTION = IdemCryption()

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
    def cryption(self):
        return self._cryption

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
        self._nickname_connections: Dict[str, ClientConnection] = {}
        self._connection_nicknames: Dict[ClientConnection, str] = {}

    def get_connection(self, nickname: str) -> Optional[ClientConnection]:
        return self._nickname_connections.get(nickname, None)

    def get_nickname(self, connection: ClientConnection) -> Optional[str]:
        return self._connection_nicknames.get(connection, None)

    def get_user_list(self) -> List[str]:
        return list(self._nickname_connections.keys())

    def register(self, nickname: str, client_connection: ClientConnection) -> None:
        with self._lock:
            if self._connection_nicknames.get(client_connection) is not None:
                raise RegistrationError("Connection already registered.")
            if self._nickname_connections.get(nickname) is not None:
                raise RegistrationError("Nickname already registered.")

            self._connection_nicknames[client_connection] = nickname
            self._nickname_connections[nickname] = client_connection

    def deregister_connection(self, client_connection: ClientConnection) -> None:
        with self._lock:
            if client_connection in self._connection_nicknames:
                nickname = self._connection_nicknames[client_connection]
                del self._connection_nicknames[client_connection]
                del self._nickname_connections[nickname]

    def deregister_nickname(self, nickname: str) -> None:
        with self._lock:
            if nickname in self._nickname_connections:
                connection = self._nickname_connections[nickname]
                del self._nickname_connections[nickname]
                del self._connection_nicknames[connection]


class EncryptionMessageHandler(socketserver.BaseRequestHandler, ConnectionHandler):
    IDEM_CRYPTION = IdemCryption()
    LOGGER = logging.getLogger(f"{__name__}[EncryptionMessageHandler]")

    @property
    def user_storage(self) -> UserStorage:
        return self.server.user_storage

    @property
    def client_storage(self) -> ClientStorage:
        return self.server.client_storage

    def setup(self):
        pass

    def handle(self):
        heading, data = self.receive_data(self.request)
        client_request: ClientRequest = self.client_storage.get_client_request(data)
        if client_request.request.command_or_response in self.COMMANDS:
            self.COMMANDS[client_request.request.command_or_response](
                self, client_request
            )
        else:
            self.handle_error("No such command")

    def handle_error(self, message: str):
        response = self.plain_response(Request(Response.ERROR, Message(message)))
        self.request.sendall(response)

    def plain_response(self, request: Request):
        return self.IDEM_CRYPTION.prepare_request_and_encrypt(request)

    def _connect_command(self, client_request: ClientRequest) -> None:
        encrypted_request = client_request.connection.prepare_encrypted_symmetric_key()
        self.request.sendall(encrypted_request)

    def _register_command(self, client_request: ClientRequest) -> None:
        client_response_address, client_nickname = client_request.request.message.data
        host = self.client_address[0]
        port = client_response_address[1]
        client_request.connection.communication_address = (host, port)

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

    def _get_user_list_command(self, client_request: ClientRequest) -> None:
        user_list = self.user_storage.get_user_list()
        encrypted_message = client_request.connection.encrypt(
            Request(Response.USER_LIST, Message.from_data(user_list))
        )
        self.request.sendall(encrypted_message)

    def _communicate_command(self, client_request: ClientRequest) -> None:
        chat_message = ChatMessage.from_message(client_request.request.message)
        receiver_connection = self.user_storage.get_connection(chat_message.receiver)
        if receiver_connection is None:
            encrypted_error_message = client_request.connection.encrypt(
                Request(Response.USER_NOT_REGISTERED, Message("No such user"))
            )
            self.request.sendall(encrypted_error_message)
            return

        sender_nickname = self.user_storage.get_nickname(client_request.connection)
        if sender_nickname is None:
            encrypted_error_message = client_request.connection.encrypt(
                Request(Response.CLIENT_NOT_REGISTERED, Message("Register first"))
            )
            self.request.sendall(encrypted_error_message)
            return

        chat_message.sender = sender_nickname

        response = receiver_connection.send_request(
            Request(client_request.request.command_or_response, chat_message)
        )
        encrypted_response = client_request.connection.encrypt(response)
        self.request.sendall(encrypted_response)

    def finish(self):
        pass

    COMMANDS: Dict[Command, Callable] = {
        Command.CONNECT: _connect_command,
        Command.CONNECT_TO_USER: _communicate_command,
        Command.MESSAGE: _communicate_command,
        Command.GET_USER_LIST: _get_user_list_command,
        Command.REGISTER: _register_command,
    }


class EncryptionMessageServer(socketserver.ThreadingTCPServer):
    LOGGER = logging.getLogger(f"{__name__}[EncryptionMessageServer]")

    def __init__(self, server_address, handler_class=EncryptionMessageHandler):
        super().__init__(server_address, handler_class)
        self.client_storage = ClientStorage()
        self.user_storage = UserStorage()
