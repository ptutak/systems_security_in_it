import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk
from typing import Any, Optional, Union, List

from .client import Client, Observer, ObserverCreator


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


class ServerConnection(tk.Frame):
    def __init__(self, master, client: Client):
        super().__init__(master)
        self.winfo_toplevel().title(f"Server: {client.communication_address}")


class GuiClient(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.winfo_toplevel().title("Client")
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
        client = Client((server_address, port), ObserverCreator())
        ServerConnection(new_window, client)
