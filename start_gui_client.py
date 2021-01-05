#!/usr/bin/python
import tkinter as tk
import tkinter.font as tkFont

from encrypted_comm.gui_client import GuiClient, set_default_font_size

root = tk.Tk()

set_default_font_size(["TkDefaultFont", "TkTextFont", "TkFixedFont"], 16)

gui_client = GuiClient(root)
gui_client.mainloop()
