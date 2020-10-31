import logging
import socketserver
import threading
from typing import Dict, Tuple, Optional
from constants import HEADING_BYTEORDER, HEADING_LENGTH, HEADING_SIGNED


class ClientConnection:
    def __init__(self):
        self.lock = threading.Lock()


class ClientStorage:
    def __init__(self):
        self._lock = threading.Lock()
        self._clients: Dict[Tuple[str, int], ClientConnection] = {}

    def get_client(self, client_id: Tuple[str, int]) -> Optional[ClientConnection]:
        with self._lock:
            if client_id in self._clients:
                return self._clients[client_id]
            return None

    def _create_client(self, client_id):
        pass

    def _create_sym_key(self):
        pass


class EncryptionMessageHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(self, request, client_address, server)
        self.logger = logging.getLogger(f"{__name__}[EncryptionMessageHandler]")

    def setup(self):
        pass

    def handle(self):
        data = self._get_data(self.request)
        self.server.client_storage.get_client(self.client_address, data)

    @classmethod
    def _get_data(self, request):
        heading = request.recv(HEADING_LENGTH)
        message_length = int.from_bytes(
            heading, byteorder=HEADING_BYTEORDER.value, signed=HEADING_SIGNED,
        )
        message = request.recv(message_length)
        return (heading, message)

    def finish(self):
        pass


class EncryptionMessageServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, handler_class=EncryptionMessageHandler):
        super().__init__(self, server_address, handler_class)
        self.logger = logging.getLogger(f"{__name__}[EncryptionMessageServer]")
        self.client_storage = ClientStorage()
