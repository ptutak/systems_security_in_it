#!/usr/bin/python
import logging

from encrypted_comm.client import Client, Observer, ObserverCreator

LOGGER = logging.getLogger(__name__)


class Printer(Observer):
    def __init__(self, id):
        self.id = id

    def update(self, nickname: str, message: str):
        print(self.id, nickname, message)


class PrinterCreator(ObserverCreator):
    def __init__(self):
        self._counter = -1

    def create(self) -> Observer:
        self._counter += 1
        return Printer(self._counter)


new_client = Client(("127.0.0.1", 7000), PrinterCreator())


def handle_command(client: Client, command: str):
    try:
        if command == "%user_list":
            result = client.get_user_list()
            print(result)
        elif command.startswith("%register"):
            nickname = command.split(" ")[1]
            client.register(nickname)
        elif command.startswith("%connect_to_user"):
            nickname = command.split(" ")[1]
            client.connect_to_user(nickname)
            while True:
                message = input("Message:")
                client.send_message(nickname, message)
    except Exception as e:
        LOGGER.exception(e)


new_client.connect_to_server()

while True:
    command = input("Command:")
    if command.startswith("%"):
        handle_command(new_client, command)
