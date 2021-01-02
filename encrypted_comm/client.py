import socket
import socketserver
import threading
from typing import List, Tuple

from .common import (
    AsymmetricDecryption,
    Command,
    Cryption,
    FernetCryption,
    IdentCryption,
    Message,
    RSACryption,
    Request,
    RequestReceiver,
    Response,
)

from .constants import HASHING_ALGORITHM
from .exception import AuthenticationError


class ClientConnection:
    pass


class ClientStorage:
    def __init__(self):
        self._lock = threading.Lock()
        self._storage = {}

    def update_list(self, client_list: List[str]) -> None:
        with self._lock:
            for client in client_list:
                if client not in self._storage:
                    self._storage[client] = None
            for client in self._storage:
                if client not in client_list:
                    del self._storage[client]

    def get_client(self, nickname: str) -> ClientConnection:
        pass


class CommunicationHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server) -> None:
        super().__init__(request, client_address, server)

    def handle(self) -> None:
        if self.request.client_address != self.server.destination_server_address:
            return


class CommunicationServer(socketserver.ThreadingTCPServer):
    def __init__(
        self,
        server_address,
        *,
        destination_server_address,
        handler_class=CommunicationHandler,
    ) -> None:
        super().__init__(server_address, handler_class)
        self.destination_server_address = destination_server_address
        self.client_storage = ClientStorage()


class ServerConnection:
    def __init__(self, sym_key):
        pass


class Client(RequestReceiver):
    ZERO_CRYPTION = IdentCryption()

    def __init__(self, server_address: Tuple[str, int]) -> int:
        self._server_address = server_address
        self._server_rsa_cryption = RSACryption()
        self._private_key_decryption: AsymmetricDecryption = AsymmetricDecryption(
            self._server_rsa_cryption
        )
        self._communication_server = None
        self._communication_server_thread = None
        self._server_cryption: Cryption = IdentCryption()

    def initiate_communication_server(self):
        self._communication_server = CommunicationServer(
            ("localhost", 0),
            handler_class=CommunicationHandler,
            destination_server_address=self._server_address,
        )
        self._communication_server_thread = threading.Thread(
            target=self._communication_server.serve_forever
        )
        self._communication_server_thread.daemon = True
        self._communication_server_thread.start()

    def connect_to_server(self):
        unencrypted_public_key = self._prepare_unencrypted_public_key_request()
        data_with_secret_uuid = self.ZERO_CRYPTION.prepare_request_and_encrypt(
            unencrypted_public_key
        )
        encrypted_request = self._send_data_and_receive(data_with_secret_uuid)
        request = self._private_key_decryption.decrypt_and_get_request(
            encrypted_request
        )
        if request.command_or_response != Response.CONNECTION_SUCCESS:
            raise RuntimeError("Connection failed")
        uuid = self._private_key_decryption.uuid
        secret_uuid = self._private_key_decryption.secret_uuid
        symmetric_key, symmetric_key_hash = request.message.data
        if HASHING_ALGORITHM(symmetric_key).hexdigest() != symmetric_key_hash:
            raise AuthenticationError("Error while processing keys")
        self._server_cryption = FernetCryption(uuid, secret_uuid, symmetric_key)

    def register(self, nickname: str) -> bool:
        if self._communication_server is None:
            self.initiate_communication_server()
        request = Request(
            Command.REGISTER,
            Message.from_data((self._communication_server.server_address, nickname)),
        )
        response = self.send_request(request)
        if response.command_or_response == Response.NICKNAME_ALREADY_USED:
            return False
        elif response.command_or_response == Response.NICKNAME_REGISTRATION_SUCCESS:
            return True
        else:
            raise RuntimeError("Unexpected response")

    def get_user_list(self) -> List[str]:
        request = Request(Command.GET_USER_LIST, Message.zero_message())
        response = self.send_request(request)
        if response.command_or_response != Response.USER_LIST:
            raise RuntimeError("Unexpected response")
        return response.message.data

    def connect_to_user(self, nickname: str) -> bool:
        request = Request(Command.CONNECT_TO_USER, Message())

    def send_message(self, nickname: str, message: str) -> bool:
        request = Request(Command.MESSAGE, Message.from_data(Request()))

    def send_request(self, request: Request) -> Request:
        encrypted_request = self._encrypt(request)
        encrypted_response = self._send_data_and_receive(encrypted_request)
        return self._decrypt(encrypted_response)

    def _prepare_unencrypted_public_key_request(self) -> Request:
        serialized_public_key = self._server_rsa_cryption.public_key_serialized
        public_key_hash = HASHING_ALGORITHM(serialized_public_key).hexdigest()
        request = Request(
            Command.CONNECT, Message.from_data((serialized_public_key, public_key_hash))
        )
        return request

    def _encrypt(self, request: Request) -> bytes:
        return self._server_cryption.prepare_request_and_encrypt(request)

    def _decrypt(self, encrypted_request: bytes) -> Request:
        return self._server_cryption.decrypt_and_get_request(encrypted_request)

    def _send_data_and_receive(self, encrypted_data: bytes):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.connect(self._server_address)
            connection.sendall(encrypted_data)
            heading, data = self.receive_data(connection)
            return data
