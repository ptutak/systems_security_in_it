import tkinter as tk
from tkinter import ttk
from typing import Optional

from .client import Client, Observer, ObserverCreator


class GuiClient(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self._client: Optional[Client] = None

    def initialize_client(self, server_address):
        self._client = Client(server_address, ObserverCreator())
