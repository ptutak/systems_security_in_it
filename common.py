from enum import Enum


class Command(Enum):
    CONNECT = "connect"
    REGISTER_NICKNAME = "register_nickname"
    SEND_MESSAGE = "send_message"
    GET_USER_LIST = "get_user_list"


class Response(Enum):
    NICKNAME_ALREADY_USED = "nickname_already_used"
    USER_LIST = "user_list"


class Message:
    def __init__(self, message, receiver):
        self.receiver = receiver
        self.message = message
        self.sender = None
