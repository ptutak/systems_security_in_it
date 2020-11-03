import pickle
import socket
import socketserver
import threading
from typing import List, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import PublicFormat

from security_of_it_systems.common import Command

from .constants import (
    HASHING_ALGORITHM,
    HEADING_BYTEORDER,
    HEADING_LENGTH,
    HEADING_SIGNED,
    ZERO_UUID,
)


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
        super().__init__(server_address, handler_class=handler_class)
        self.destination_server_address = destination_server_address
        self.client_storage = ClientStorage()


class ServerConnection:
    def __init__(self, sym_key):
        pass


class IdentCryption:
    def encrypt(self, data):
        return data

    def decrypt(self, data):
        return data


class Client:
    def __init__(self, server_address: Tuple[str, int]) -> int:
        self._server_address = server_address
        self._server_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self._server_public_key = self._server_private_key.public_key()
        self._communication_server = None
        self._uuid = ZERO_UUID
        self._secret_uuid = ZERO_UUID
        self._cryption = IdentCryption()

    def initiate_communication_server(self):
        self._communication_server = CommunicationServer(
            ("localhost", 0),
            handler_class=CommunicationHandler,
            destination_server_address=self._server_address,
        )
        communication_server_thread = threading.Thread(
            target=self._communication_server.serve_forever
        )
        communication_server_thread.daemon = True
        communication_server_thread.start()

    def connect_to_server(self):
        data = self.prepare_unencrypted_public_key()
        data_with_secret_uuid = ZERO_UUID + data
        response = self.send_data_and_get_response(data_with_secret_uuid)
        # TODO: decrypt the response

    def prepare_unencrypted_public_key(self) -> bytes:
        stored_public_key = self._server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
        public_key_hash = HASHING_ALGORITHM(stored_public_key).hexdigest()
        data = (Command.CONNECT, (stored_public_key, public_key_hash))
        return pickle.dumps(data)

    def encrypt(self, message: object) -> bytes:
        return self._cryption.encrypt(self._secret_uuid + pickle.dumps(message))

    def decrypt(self, encrypted_message: bytes) -> object:
        decrypted = self._cryption.decrypt(encrypted_message)
        return pickle.loads(decrypted)

    def send_data_and_get_response(self, encrypted_data: bytes):
        data_with_uuid = self._uuid + encrypted_data
        data_length = len(data_with_uuid)
        heading = data_length.to_bytes(
            length=HEADING_LENGTH, byteorder=HEADING_BYTEORDER, signed=HEADING_SIGNED
        )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.connect(self._server_address)
            connection.sendall(heading + data_with_uuid)
            recv_heading = connection.recv(HEADING_LENGTH)
            data_length = int.from_bytes(
                recv_heading, byteorder=HEADING_BYTEORDER.value, signed=HEADING_SIGNED,
            )
            data = connection.recv(data_length)
            return (heading, data)
