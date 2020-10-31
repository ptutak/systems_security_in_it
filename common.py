from enum import Enum


class Command(Enum):
    CONNECT = "connect"
    REGISTER_NICKNAME = "register_nickname"
    SEND_MESSAGE = "send_message"


class Message:
    def __init__(self, receiver, message):
        self.receiver = receiver
        self.message = message
