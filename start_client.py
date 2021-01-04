#!/usr/bin/python

from encrypted_comm.client import Client, Observer, ObserverCreator


class Printer(Observer):
    def __init__(self, id):
        self.id = id

    def update(self, message: str):
        print(self.id, message)


class PrinterCreator(ObserverCreator):
    def __init__(self):
        self._counter = -1

    def create(self) -> Observer:
        self._counter += 1
        return Printer(self._counter)


new_client = Client(("127.0.0.1", 7000), PrinterCreator())

new_client.connect_to_server()
result = new_client.register("New Nickname")
print(result)
user_list = new_client.get_user_list()

print(user_list)

result = new_client.connect_to_user("New Nickname")

print(result)
