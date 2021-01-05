import logging
import pickle
import socket
import socketserver
import threading
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple

from cryptography.fernet import Fernet

from .common import (
    AsymmetricDecryption,
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
    RSACryption,
    RSAEncryption,
)
from .constants import CLIENT_REFRESH_TIME, HASHING_ALGORITHM
from .exception import AuthenticationError

LOGGER = logging.getLogger(__name__)


class Observer(ABC):
    @abstractmethod
    def update(self, nickname: str, message: str) -> None:
        """
        Update observer with a state message
        """

    @abstractmethod
    def close(self) -> None:
        """
        Closes the connection
        """


class ObserverCreator(ABC):
    @abstractmethod
    def create(self, nickname: str) -> Observer:
        """
        Creates an observer
        """


class ClientConnection:
    def __init__(self, sym_key: bytes):
        self._cryption = Fernet(sym_key)
        self._lock = threading.Lock()
        self._observers: List[Observer] = list()

    def encrypt(self, data: object) -> bytes:
        return self._cryption.encrypt(pickle.dumps(data))

    def decrypt(self, message: bytes) -> object:
        return pickle.loads(self._cryption.decrypt(message))

    def close(self) -> None:
        with self._lock:
            for observer in self._observers:
                observer.close()
        self._observers.clear()

    def __del__(self):
        self.close()

    def attach(self, observer: Observer) -> None:
        with self._lock:
            self._observers.append(observer)

    def detach(self, observer: Observer) -> None:
        with self._lock:
            try:
                self._observers.remove(observer)
            except ValueError:
                return

    def notify(self, nickname: str, message: str) -> None:
        with self._lock:
            for observer in self._observers:
                observer.update(nickname, message)


class ClientConnections:
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

    def new_connection(self, nickname: str, sym_key: bytes) -> ClientConnection:
        connection = ClientConnection(sym_key)
        self.register(nickname, connection)
        return connection

    def register(self, nickname: str, client_connection: ClientConnection) -> None:
        with self._lock:
            if self._connection_nicknames.get(client_connection) is not None:
                raise RuntimeError("Connection already registered.")
            if self._nickname_connections.get(nickname) is not None:
                raise RuntimeError(
                    f"Nickname already registered:{self._nickname_connections}"
                )

            self._connection_nicknames[client_connection] = nickname
            self._nickname_connections[nickname] = client_connection

    def deregister_connection(self, client_connection: ClientConnection) -> None:
        with self._lock:
            if client_connection in self._connection_nicknames:
                nickname = self._connection_nicknames[client_connection]
                del self._connection_nicknames[client_connection]
                del self._nickname_connections[nickname]
                client_connection.close()

    def deregister_nickname(self, nickname: str) -> None:
        with self._lock:
            if nickname in self._nickname_connections:
                connection = self._nickname_connections[nickname]
                del self._nickname_connections[nickname]
                del self._connection_nicknames[connection]
                connection.close()


class CommunicationHandler(socketserver.BaseRequestHandler, ConnectionHandler):

    IDEM_CRYPTION = IdemCryption()

    def __init__(self, request, client_address, server) -> None:
        super().__init__(request, client_address, server)

    @property
    def cryption(self) -> Cryption:
        return self.server.server_cryption

    @property
    def observer_creator(self) -> ObserverCreator:
        return self.server.observer_creator

    @property
    def client_connections(self) -> ClientConnections:
        return self.server.client_connections

    def receive_request(self, request) -> Request:
        data_length, data = self.receive_data(request)
        return self.decrypt(data)

    def decrypt(self, data: bytes) -> Request:
        return self.cryption.decrypt_and_get_request(data)

    def error_response(self, error_message: str) -> bytes:
        request = Request(Response.ERROR, Message(error_message))
        return self.encrypt(request)

    def encrypt(self, request: Request) -> bytes:
        return self.cryption.prepare_request_and_encrypt(request)

    def handle(self) -> None:
        request = self.receive_request(self.request)
        command = request.command_or_response
        if command not in self.COMMANDS:
            wrong_command = Request(Response.WRONG_COMMAND, Message.zero_message())
            self.request.sendall(self.encrypt(wrong_command))
            return
        self.COMMANDS[command](self, request)

    def _connect_to_user(self, request: Request) -> None:
        chat_message = ChatMessage.from_message(request.message)
        nickname = chat_message.sender
        public_key, public_key_hash = pickle.loads(chat_message.message)
        if HASHING_ALGORITHM(public_key).hexdigest() != public_key_hash:
            raise AuthenticationError("Wrong public key hash.")
        rsa_encryption = RSAEncryption.from_serialized_key(public_key)
        sym_key = Fernet.generate_key()
        sym_key_hash = HASHING_ALGORITHM(sym_key).hexdigest()
        key_data = (sym_key, sym_key_hash)
        key_data_bytes = pickle.dumps(key_data)
        encrypted_key_data_bytes = rsa_encryption.encrypt(key_data_bytes)

        request = Request(
            Response.CONNECTION_SUCCESS,
            ChatMessage(None, nickname, encrypted_key_data_bytes),
        )
        encrypted_request = self.encrypt(request)
        self.request.sendall(encrypted_request)
        new_connection = self.client_connections.new_connection(nickname, sym_key)
        new_connection.attach(self.observer_creator.create(nickname))

    def _message(self, request: Request) -> None:
        chat_message = ChatMessage.from_message(request.message)
        sender = chat_message.sender
        connection = self.client_connections.get_connection(sender)
        if connection is None:
            response = Request(Response.USER_NOT_CONNECTED, Message.zero_message())
            self.request.sendall(self.encrypt(response))
            return
        message = connection.decrypt(chat_message.message)
        response = Request(Response.MESSAGE_SUCCESS, Message.zero_message())
        self.request.sendall(self.encrypt(response))
        connection.notify(sender, message)

    def _disconnect_user(self, request: Request) -> None:
        chat_message = ChatMessage.from_message(request.message)
        connection = self.client_connections.get_connection(chat_message.sender)
        if connection is None:
            response = Request(Response.USER_NOT_CONNECTED, Message.zero_message())
            self.request.sendall(self.encrypt(response))
            return
        response = Request(Response.DISCONNECTION_SUCCESS, Message.zero_message())
        self.request.sendall(self.encrypt(response))
        self.client_connections.deregister_connection(connection)

    COMMANDS = {
        Command.CONNECT_TO_USER: _connect_to_user,
        Command.MESSAGE: _message,
        Command.DISCONNECT_USER: _disconnect_user,
    }


class CommunicationServer(socketserver.ThreadingTCPServer):
    def __init__(
        self,
        server_address,
        *,
        destination_server_address: Tuple[str, int],
        observer_creator: ObserverCreator,
        handler_class=CommunicationHandler,
    ) -> None:
        super().__init__(server_address, handler_class)
        self.destination_server_address = destination_server_address
        self.client_connections = ClientConnections()
        self.server_cryption = IdemCryption()
        self.observer_creator = observer_creator


class ConnectionPinger:
    def __init__(
        self, bytes_request: bytes, server_address: Tuple[str, int], time_interval: int
    ) -> None:
        self._request = bytes_request
        self._server_address = server_address
        self._interval = time_interval
        self._flag = threading.Event()
        self._flag.clear()

    def run(self):
        while not self._flag.is_set():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.connect(self._server_address)
                connection.sendall(self._request)
            self._flag.wait(self._interval)

    def close(self):
        self._flag.set()


class Client(EncryptingConnectionHandler):
    ZERO_CRYPTION = IdemCryption()

    def __init__(
        self, server_address: Tuple[str, int], observer_creator: ObserverCreator
    ) -> int:
        self._server_address = server_address
        self._server_rsa_cryption = RSACryption()
        self._private_key_decryption: AsymmetricDecryption = AsymmetricDecryption(
            self._server_rsa_cryption
        )
        self._communication_server: Optional[CommunicationServer] = None
        self._communication_server_thread = None
        self._server_cryption: Cryption = IdemCryption()
        self._observer_creator = observer_creator
        self._pinger: Optional[ConnectionPinger] = None
        self._pinger_thread = None
        self._nickname = None
        self.initialize_communication_server()

    @property
    def communication_address(self) -> Tuple[str, int]:
        return self._server_address

    @property
    def cryption(self) -> Cryption:
        return self._server_cryption

    def initialize_pinger(self) -> None:
        request = Request(Command.PING, Message.zero_message())
        pinger_request = self.encrypt(request)
        self._pinger = ConnectionPinger(
            pinger_request, self.communication_address, CLIENT_REFRESH_TIME
        )
        self._pinger_thread = threading.Thread(target=self._pinger.run)
        self._pinger_thread.daemon = True
        self._pinger_thread.start()

    def close_connection(self):
        if self._pinger is not None:
            self._pinger.close()
        if self._communication_server is not None:
            self._communication_server.shutdown()

    def __del__(self):
        self.close_connection()

    def initialize_communication_server(self) -> None:
        self._communication_server = CommunicationServer(
            ("localhost", 0),
            destination_server_address=self.communication_address,
            observer_creator=self._observer_creator,
            handler_class=CommunicationHandler,
        )
        self._communication_server_thread = threading.Thread(
            target=self._communication_server.serve_forever
        )
        self._communication_server_thread.daemon = True
        self._communication_server_thread.start()

    def connect_to_server(self):
        unencrypted_public_key_request = self._prepare_unencrypted_public_key_request()

        prepared_datagram = self.ZERO_CRYPTION.prepare_request_and_encrypt(
            unencrypted_public_key_request
        )

        encrypted_response = self.send_data_and_receive_response(
            prepared_datagram, self._server_address
        )

        request = self._private_key_decryption.decrypt_and_get_request(
            encrypted_response
        )

        if request.command_or_response != Response.CONNECTION_SUCCESS:
            raise RuntimeError(
                f"Connection failed {request.command_or_response} {request.message}"
            )

        uuid = self._private_key_decryption.uuid
        secret_uuid = self._private_key_decryption.secret_uuid
        symmetric_key, symmetric_key_hash = request.message.data

        if HASHING_ALGORITHM(symmetric_key).hexdigest() != symmetric_key_hash:
            raise AuthenticationError("Error while processing keys")

        self._server_cryption = FernetCryption(uuid, secret_uuid, symmetric_key)
        self._communication_server.server_cryption = self._server_cryption
        if self._pinger is not None:
            self._pinger.close()
        self.initialize_pinger()

    def _prepare_unencrypted_public_key_request(self) -> Request:
        serialized_public_key = self._server_rsa_cryption.public_key_serialized
        public_key_hash = HASHING_ALGORITHM(serialized_public_key).hexdigest()
        request = Request(
            Command.CONNECT, Message.from_data((serialized_public_key, public_key_hash))
        )
        return request

    def register(self, nickname: str) -> None:
        request = Request(
            Command.REGISTER,
            Message.from_data((self._communication_server.server_address, nickname)),
        )
        response = self.send_request(request)
        if response.command_or_response != Response.NICKNAME_REGISTRATION_SUCCESS:
            raise RuntimeError(
                f"Registration error: {response.command_or_response} {response.message}"
            )
        self._nickname = nickname

    def get_user_list(self) -> List[str]:
        request = Request(Command.GET_USER_LIST, Message.zero_message())
        response = self.send_request(request)
        if response.command_or_response != Response.USER_LIST:
            raise RuntimeError("Unexpected response")
        user_list = response.message.data
        return user_list

    def connect_to_user(self, nickname: str) -> None:
        rsa_cryption = RSACryption()
        serialized_key = rsa_cryption.public_key_serialized
        data = (serialized_key, HASHING_ALGORITHM(serialized_key).hexdigest())
        bytes_data = pickle.dumps(data)
        request = Request(
            Command.CONNECT_TO_USER, ChatMessage(None, nickname, bytes_data)
        )
        response = self.send_request(request)
        if response.command_or_response != Response.CONNECTION_SUCCESS:
            raise RuntimeError(
                f"Connection failed: {response.command_or_response} {response.message}"
            )
        message = ChatMessage.from_message(response.message)

        decrypted_message = rsa_cryption.decrypt(message.message)
        symmetric_key, symmetric_key_hash = pickle.loads(decrypted_message)

        if HASHING_ALGORITHM(symmetric_key).hexdigest() != symmetric_key_hash:
            raise RuntimeError("Symmetric key hash error.")

        new_connection = self._communication_server.client_connections.new_connection(
            nickname, symmetric_key
        )
        new_connection.attach(self._observer_creator.create(nickname))

    def disconnect_user(self, nickname: str):
        connection = self._communication_server.client_connections.get_connection(
            nickname
        )

        if connection is None:
            return

        request = Request(
            Command.DISCONNECT_USER, ChatMessage(None, nickname, connection.encrypt(""))
        )
        response = self.send_request(request)

        if response.command_or_response != Response.DISCONNECTION_SUCCESS:
            raise RuntimeError(
                f"Disconnection failed {response.command_or_response} {response.message}"
            )

        self._communication_server.client_connections.deregister_connection(connection)

    def remove_user(self, nickname: str):
        connection = self._communication_server.client_connections.get_connection(
            nickname
        )

        if connection is None:
            return

        self._communication_server.client_connections.deregister_connection(connection)

    def send_message(self, nickname: str, message: str) -> None:
        connection = self._communication_server.client_connections.get_connection(
            nickname
        )

        if connection is None:
            raise RuntimeError(f"No such user {nickname}")

        request = Request(
            Command.MESSAGE, ChatMessage(None, nickname, connection.encrypt(message))
        )
        response = self.send_request(request)
        if response.command_or_response != Response.MESSAGE_SUCCESS:
            raise RuntimeError(
                f"Sending message failed: {response.command_or_response} {response.message}"
            )
        connection.notify(self._nickname, message)
