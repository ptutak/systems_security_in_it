import logging
import tkinter as tk
import tkinter.font as tkfont
from threading import Thread
from time import sleep
from tkinter import ttk
from typing import List, Union

from .client import Client, Observer, ObserverCreator
from .constants import CLIENT_REFRESH_TIME

LOGGER = logging.getLogger(__name__)


def set_default_font_size(fonts: List[str], size: int):
    for font in fonts:
        tkinter_font = tkfont.nametofont(font)
        tkinter_font.configure(size=size)


class EntryWithLabel(tk.Frame):
    def __init__(self, master, name: str, var_value: Union[str, int]):
        super().__init__(master)

        if isinstance(var_value, int):
            self._variable: Union[tk.IntVar, tk.StringVar] = tk.IntVar(value=var_value)
        elif isinstance(var_value, str):
            self._variable = tk.StringVar(value=var_value)
        else:
            raise RuntimeError("Value type not supported")

        self._label = tk.Label(self, text=name)
        self._label.grid(row=0, column=0)
        self._entry = tk.Entry(self, textvariable=self._variable)
        self._entry.grid(row=1, column=0)

    @property
    def value(self) -> Union[str, int]:
        return self._variable.get()


class PopupWindow(tk.Frame):
    def __init__(self, title: str, text: str):
        new_window = tk.Toplevel()
        super().__init__(new_window)
        position_right = int(self.winfo_screenwidth() / 2)
        position_down = int(self.winfo_screenheight() / 2)
        new_window.geometry(f"+{position_right}+{position_down}")
        self.pack()
        self.winfo_toplevel().title(title)
        self._label = tk.Label(self, text=text)
        self._label.pack()
        self._ok_button = tk.Button(self, text="Ok", command=new_window.destroy)
        self._ok_button.pack()


class ServerConnection(tk.Frame):
    def __init__(self, master, client: Client):
        super().__init__(master)
        self.winfo_toplevel().title(f"Server: {client.communication_address}")
        position_right = int(self.winfo_screenwidth() / 2)
        position_down = int(self.winfo_screenheight() / 2)
        master.geometry(f"+{position_right}+{position_down}")
        self.grid(row=0, column=0)
        self._master = master
        self._client = client
        try:
            self._client.connect_to_server()
        except Exception as e:
            PopupWindow("Connection Error", f"Error when connecting to server: {e}")
            LOGGER.error(f"Error when connecting to server: {e}")
            master.destroy()
            return

        self._connect_to_user_button = tk.Button(
            self, text="Connect to Users", command=self._connect_to_users
        )
        self._connect_to_user_button.grid(row=1, column=0)

        self._register_entry = EntryWithLabel(self, "Nickname:", "MyName")
        self._register_entry.grid(row=2, column=0)
        self._register_button = tk.Button(self, text="Register", command=self._register)
        self._register_button.grid(row=3, column=0)

        self._label = tk.Label(self, text="User list:")
        self._label.grid(row=0, column=1)
        self._y_scroll = tk.Scrollbar(self, orient=tk.VERTICAL)
        self._y_scroll.grid(row=1, column=2, sticky=tk.N + tk.S)

        self._list = tk.StringVar()
        self._list_box = tk.Listbox(
            self, yscrollcommand=self._y_scroll.set, listvariable=self._list,
        )
        self._y_scroll["command"] = self._list_box.yview
        self._list_box.grid(row=1, column=1)

        self._list_updating_thread = Thread(target=self._list_update)
        self._list_updating_thread.daemon = True
        self._list_updating_thread.start()

    def _register(self):
        value = self._register_entry.value
        if value.strip() == "":
            PopupWindow("Invalid value", "Nickname cannot be empty")
            return
        try:
            self._client.register(value.strip())
            self._update_user_list()
        except Exception as e:
            PopupWindow("Registration error", f"{e}")
            LOGGER.error(f"Registration error: {e}")

    def _list_update(self):
        while True:
            if not self.winfo_exists():
                return
            self._update_user_list()
            sleep(CLIENT_REFRESH_TIME)

    def _update_user_list(self):
        user_list = self._client.get_user_list()
        selected = self._list_box.curselection()
        selected_names = list(self._list_box.get(selection) for selection in selected)
        activated = None
        for user in selected_names:
            if user in user_list:
                activated = user_list.index(user)
        self._list_box.delete(0, tk.END)
        self._list_box.insert(0, *user_list)
        if activated is not None:
            self._list_box.selection_set(activated)

    def _connect_to_users(self):
        selected_users = self._list_box.curselection()
        selected_user_names = list(
            item
            for selection in selected_users
            for item in self._list_box.get(selection)
        )

        for user in selected_user_names:
            self._client.connect_to_user(user)


class ChatWindow(tk.Frame, Observer):
    def __init__(self, master):
        super().__init__(master)
        position_right = int(self.winfo_screenwidth() / 2)
        position_down = int(self.winfo_screenheight() / 2)
        master.geometry(f"+{position_right}+{position_down}")
        self.grid(row=0, column=0)
        self._master = master

        self._label = tk.Label(self, text="Chat Window")
        self._label.grid(row=0, column=0)

    def update(self, nickname: str, message: str) -> None:
        pass


class ChatWindowCreator(ObserverCreator):
    def __init__(self, master):
        self._master = master

    def create(self) -> Observer:
        new_window = tk.Toplevel(self._master)
        return ChatWindow(new_window)


class Mock:
    def __init__(self, comm_address):
        self.communication_address = comm_address


class GuiClient(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.winfo_toplevel().title("Client")
        position_right = int(self.winfo_screenwidth() / 2)
        position_down = int(self.winfo_screenheight() / 2)
        master.geometry(f"+{position_right}+{position_down}")

        self._master = master
        self.grid(row=0, column=0)

        self._address_entry = EntryWithLabel(self, "Server Address:", "127.0.0.1")
        self._address_entry.grid(row=0, column=0)

        self._port_entry = EntryWithLabel(self, "Port:", 7000)
        self._port_entry.grid(row=1, column=0)

        self._connect_button = tk.Button(
            self, text="Connect", command=self._initialize_client
        )
        self._connect_button.grid(row=2, column=0)

    def _initialize_client(self):
        server_address = self._address_entry.value
        port = self._port_entry.value
        new_window = tk.Toplevel(self._master)
        client = Client((server_address, port), ChatWindowCreator(self))
        ServerConnection(new_window, client)
