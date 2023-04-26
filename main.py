import os.path
import tkinter
import customtkinter as ctk
from AuroraByte import encrypt, decrypt
import secrets
from threading import Thread


ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class Cipher(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.filepath = None
        self.keypath = None

        # configure window
        self.title("AuroraByte Encryption")
        self.geometry(f"{500}x{580}")
        self.resizable(False, False)

        # create title frame
        self.title_frame = ctk.CTkFrame(self, corner_radius=0)
        self.title_frame.grid(row=0, column=0, sticky="ns")
        self.title_frame.rowconfigure(1, weight=1)
        # add the title
        self.title = ctk.CTkLabel(self.title_frame, text="AuroraByte Cipher", font=ctk.CTkFont(size=20, weight="bold"))
        self.title.grid(row=0, column=0, padx=161, pady=(20, 20))

        # create main frame
        self.frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.frame.grid(row=1, column=0, sticky="ns")
        self.frame.grid_rowconfigure(5, weight=1)

        # add select file label
        self.selected_file = ctk.CTkLabel(self.frame, text="No file selected", font=ctk.CTkFont(size=20, weight="bold"))
        self.selected_file.grid(row=1, column=0, padx=20, pady=20)

        # add select file button
        self.file_select = ctk.CTkButton(self.frame, text="Select File", command=self.select_file)
        self.file_select.grid(row=2, column=0, padx=20, pady=(10, 30))

        # add key file label
        self.selected_key = ctk.CTkLabel(self.frame, text="No key selected", font=ctk.CTkFont(size=20, weight="bold"))
        self.selected_key.grid(row=3, column=0, padx=20, pady=20)

        # add select key button
        self.key_select = ctk.CTkButton(self.frame, text="Select Key", command=self.select_key)
        self.key_select.grid(row=4, column=0, padx=20, pady=(10, 30))

        # add encrypt button
        self.encrypt_btn = ctk.CTkButton(self.frame, text="Encrypt", command=self.encrypt)
        self.encrypt_btn.grid(row=5, column=0, padx=20, pady=(50, 10))

        # add decrypt button
        self.decrypt_btn = ctk.CTkButton(self.frame, text="Decrypt", command=self.decrypt)
        self.decrypt_btn.grid(row=6, column=0, padx=20, pady=10)

        # add messages label
        self.message_label = ctk.CTkLabel(self.frame, text="", font=ctk.CTkFont(size=20, weight="bold"))
        self.message_label.grid(row=7, column=0, padx=20, pady=20)

    def encrypt(self):
        self.message_label.configure(text="Encryption in progress...")
        if self.filepath in [None, ""]:
            self.message_label.configure(text="You need to select a file to encrypt!")
            return

        # generate private key
        private_key = secrets.token_urlsafe(32)

        filepath = self.filepath.split("/")
        key_name = filepath[-1].split(".")[0] + ".key"

        with open(key_name, "wb") as key_file:
            key_file.write(private_key.encode())

        with open(self.filepath, "rb") as file:
            data = file.read()  # bytes
            encrypted_data = encrypt(str(data), private_key)

        with open(self.filepath, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data.encode())

        self.message_label.configure(text="Encryption completed!")
        self.reset()

    def decrypt(self):
        self.message_label.configure(text="Decryption in progress...")

        if self.filepath in [None, ""]:
            self.message_label.configure(text="You need to select a file to decrypt!")
            return

        elif self.keypath in [None, ""]:
            self.message_label.configure(text="You need to select a key before decrypting!")
            return

        with open(self.keypath, "rb") as key_file:
            private_key = key_file.read()

        try:
            with open(self.filepath, "rb") as file:
                data = file.read()
                decrypted_data = decrypt(str(data.decode()), private_key.decode())

            with open(self.filepath, "wb") as decrypted_file:
                decrypted_file.write(eval(decrypted_data))

            self.message_label.configure(text="Decryption completed!")
            self.reset()
        except ValueError:
            self.message_label.configure(text="Can not complete the decryption.\nFile is not encrypted with AuroraByte encryption.")

    def select_file(self):
        self.filepath = tkinter.filedialog.askopenfilename(initialdir=os.path.dirname(os.path.abspath(__file__)), title="Select File",
                                                           filetype=(("All Files", "*.*"),))

        if self.filepath != "":
            self.selected_file.configure(text=self.filepath.split("/")[-1])

    def select_key(self):
        self.keypath = tkinter.filedialog.askopenfilename(initialdir=os.path.dirname(os.path.abspath(__file__)), title="Select File",
                                                          filetype=(("Key file", "*.key"), ("All Files", "*.*")))

        if self.keypath.split(".")[-1] != "key":
            self.selected_key.configure(text="Incorrect key format.\nThe key file should have a .key extension")

        elif self.keypath != "":
            self.selected_key.configure(text=self.keypath.split("/")[-1])

    def reset(self):
        self.filepath = None
        self.keypath = None
        self.selected_file.configure(text="No file selected")
        self.selected_key.configure(text="No key selected")


if __name__ == "__main__":
    app = Cipher()
    app.mainloop()

