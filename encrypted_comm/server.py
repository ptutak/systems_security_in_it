import logging
import socketserver
import threading
import time
import uuid
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from cryptography.fernet import Fernet

from .common import (
    AsymmetricEncryption,
    ChatMessage,
    Command,
    ConnectionHandler,
    Cryption,
    EncryptingConnectionHandler,
    FernetCryption,
    IdemCryption,
    Message,
    Request,
    Response,
    RSAEncryption,
)
from .constants import CLIENT_IDLE_TIME, HASHING_ALGORITHM
from .exception import (
    AuthenticationError,
    ConnectionError,
    InvalidCommand,
    RegistrationError,
    ResponseAddressError,
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
        try:
            request = self.ZERO_CRYPTION.decrypt_and_get_request(register_request)
        except AuthenticationError as e:
            raise ConnectionError("No leading ZERO UUID on connection creation.") from e

        command, public_key_composit = request.command_or_response, request.message.data
        if command != Command.CONNECT:
            raise InvalidCommand("Expected CONNECT command.")

        public_key, public_key_sha256 = public_key_composit
        if HASHING_ALGORITHM(public_key).hexdigest() != public_key_sha256:
            raise RuntimeError("Wrong public key hash")

        encryption = RSAEncryption.from_serialized_key(public_key)

        self._public_key_cryption: AsymmetricEncryption = AsymmetricEncryption(
            client_uuid, secret_uuid, encryption
        )

        self._update_time = time.time()

    def is_active(self):
        return time.time() - self._update_time < CLIENT_IDLE_TIME

    def update(self):
        self._update_time = time.time()

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
            connection.update()
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

    def get_clients(self) -> List[ClientConnection]:
        return list(self._clients.values())

    def discard_client(self, client: ClientConnection):
        uuid = client.cryption.uuid.bytes
        with self._clients_lock:
            if uuid in self._clients:
                del self._clients[uuid]

    def discard_clients(self, clients: List[ClientConnection]):
        with self._clients_lock:
            for client in clients:
                uuid = client.cryption.uuid.bytes
                if uuid in self._clients:
                    del self._clients[uuid]


class UserStorage:
    def __init__(self):
        self._lock = threading.Lock()
        self._nickname_connections: Dict[str, ClientConnection] = {}
        self._connection_nicknames: Dict[ClientConnection, str] = {}

    def get_connection(self, nickname: str) -> Optional[ClientConnection]:
        connection = self._nickname_connections.get(nickname, None)
        if connection is not None:
            if connection.is_active():
                connection.update()
        return connection

    def get_nickname(self, connection: ClientConnection) -> Optional[str]:
        nickname = self._connection_nicknames.get(connection, None)
        if nickname is not None:
            if connection.is_active():
                connection.update()
        return nickname

    def get_user_list(self) -> List[str]:
        return list(self._nickname_connections.keys())

    def get_clients(self) -> List[ClientConnection]:
        return list(self._connection_nicknames.keys())

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
            self._delete_connection(client_connection)

    def deregister_connections(self, connections: List[ClientConnection]) -> None:
        with self._lock:
            for connection in connections:
                self._delete_connection(connection)

    def _delete_connection(self, connection: ClientConnection) -> None:
        if connection in self._connection_nicknames:
            nickname = self._connection_nicknames[connection]
            del self._connection_nicknames[connection]
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
        try:
            client_request: ClientRequest = self.client_storage.get_client_request(data)

        except Exception as e:
            self.handle_error(f"{e}")
            return

        try:
            if client_request.request.command_or_response in self.COMMANDS:
                self.COMMANDS[client_request.request.command_or_response](
                    self, client_request
                )
            else:
                self.handle_encrypted_error(client_request, "No such command")
        except Exception as e:
            self.handle_encrypted_error(client_request, f"{e}")

    def handle_error(self, message: str):
        response = self.plain_response(Request(Response.ERROR, Message(message)))
        self.request.sendall(response)
        self.LOGGER.error(f"ERROR: {self.client_address} {message}")

    def handle_encrypted_error(
        self, client_request: ClientRequest, message: str
    ) -> None:
        response = Request(Response.ERROR, Message(message))
        self.request.sendall(client_request.connection.encrypt(response))
        self.LOGGER.error(
            f"ERROR: {self.client_address} {client_request.request.command_or_response} "
            f"{client_request.request.message} {message}"
        )

    def plain_response(self, request: Request):
        return self.IDEM_CRYPTION.prepare_request_and_encrypt(request)

    def _connect_command(self, client_request: ClientRequest) -> None:
        encrypted_request = client_request.connection.prepare_encrypted_symmetric_key()
        self.request.sendall(encrypted_request)

    def _register_command(self, client_request: ClientRequest) -> None:
        client_response_address, client_nickname = client_request.request.message.data

        try:
            self.server.user_storage.register(
                client_nickname, client_request.connection
            )
        except RegistrationError as e:
            encrypted_message = client_request.connection.encrypt(
                Request(Response.REGISTRATION_ERROR, Message(str(e)))
            )
        else:
            encrypted_message = client_request.connection.encrypt(
                Request(Response.NICKNAME_REGISTRATION_SUCCESS, Message.zero_message())
            )
            host = self.client_address[0]
            port = client_response_address[1]
            client_request.connection.communication_address = (host, port)

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

    def _ping_command(self, client_request: ClientRequest) -> None:
        client_request.connection.update()

    def finish(self):
        pass

    COMMANDS: Dict[Command, Callable] = {
        Command.CONNECT: _connect_command,
        Command.CONNECT_TO_USER: _communicate_command,
        Command.MESSAGE: _communicate_command,
        Command.GET_USER_LIST: _get_user_list_command,
        Command.REGISTER: _register_command,
        Command.PING: _ping_command,
    }


class ClientConnectionsCleaner:
    def __init__(
        self,
        client_storage: ClientStorage,
        user_storage: UserStorage,
        time_interval: int,
    ) -> None:
        self._client_storage = client_storage
        self._user_storage = user_storage
        self._interval = time_interval

    def run(self):
        while True:
            clients = self._client_storage.get_clients()
            offline_clients = list(
                client for client in clients if not client.is_active()
            )
            self._user_storage.deregister_connections(offline_clients)
            self._client_storage.discard_clients(offline_clients)
            time.sleep(self._interval)


class EncryptionMessageServer(socketserver.ThreadingTCPServer):
    LOGGER = logging.getLogger(f"{__name__}[EncryptionMessageServer]")

    def __init__(self, server_address, handler_class=EncryptionMessageHandler):
        super().__init__(server_address, handler_class)
        self.client_storage = ClientStorage()
        self.user_storage = UserStorage()
        self.client_cleaner = ClientConnectionsCleaner(
            self.client_storage, self.user_storage, CLIENT_IDLE_TIME
        )
        client_cleaner_thread = threading.Thread(target=self.client_cleaner.run)
        client_cleaner_thread.daemon = True
        client_cleaner_thread.start()
