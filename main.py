import os
import string
import threading
from tkinter import messagebox

import customtkinter as ctk
import psutil
from PIL import Image, ImageDraw

import DeviceEncryption

ctk.set_default_color_theme("styles.json")

class TopEncryption(ctk.CTkToplevel):
    def __init__(self, parent, device):
        super().__init__(parent)
        self.device = device
        self.title(f"Encryption of {self.device}")
        self.geometry("400x500")

        self.after(250, lambda: self.iconbitmap("images/logo_color.ico"))
        self.resizable(False, False)

        def check_password(event):
            special_chars = string.punctuation
            pw = self.passwordEntryEncryption.get()
            update_label(requirements["length"][1], len(pw) >= 8)
            update_label(
                requirements["uppercase"][1], any(char.isupper() for char in pw)
            )
            update_label(
                requirements["lowercase"][1], any(char.islower() for char in pw)
            )
            update_label(requirements["digit"][1], any(char.isdigit() for char in pw))
            update_label(
                requirements["special"][1], any(char in special_chars for char in pw)
            )

        label_height = 25

        def update_label(label, condition):
            if condition:
                label.configure(text="✔️", text_color="green")
            else:
                label.configure(text="❌", text_color="red")

        self.progressBar = ctk.CTkProgressBar(
            self, width=200, height=15, progress_color="green"
        )
        self.progressBar.set(0)
        self.progressBar.grid(row=8, column=1, columnspan=3, padx=0, sticky="ew")
        self.progressLabel = ctk.CTkLabel(self, text="0%", text_color="white")
        self.progressLabel.grid(row=8, column=4, padx=(10, 0))

        def update_progress(processed_files, total_files):
            progress = processed_files / total_files
            self.progressBar.set(progress)
            self.progressLabel.configure(text=f"{progress*100:.2f}%")

        def encryption_process():
            if not all(label[1].cget("text") == "✔️" for label in requirements.values()):
                messagebox.showerror("Error", "Please meet all password requirements!")
                return
            password = self.passwordEntryEncryption.get()

            def run_encryption():
                DeviceEncryption.encryptDirectory(
                    self.device, password, update_progress
                )
                messagebox.showinfo("Success", "Encryption completed!")

            encryption_thread = threading.Thread(target=run_encryption)
            encryption_thread.start()
            self.after(1000, check_if_running, encryption_thread, self)

        def check_if_running(thread, window):
            if thread.is_alive():
                window.after(1000, check_if_running, thread, window)
            else:
                window.destroy()
                window.update()


        requirements = {
            "length": [
                ctk.CTkLabel(
                    self,
                    text="At least 8 characters",
                    fg_color=("white", "gray75"),
                    corner_radius=8,
                    text_color="black",
                    height=20,
                    anchor="w",
                ),
                ctk.CTkLabel(self, text="❌", text_color="red", height=label_height),
            ],
            "uppercase": [
                ctk.CTkLabel(
                    self,
                    text="At least one uppercase letter",
                    fg_color=("white", "gray75"),
                    corner_radius=8,
                    text_color="black",
                    height=20,
                    anchor="w",
                ),
                ctk.CTkLabel(self, text="❌", text_color="red", height=label_height),
            ],
            "lowercase": [
                ctk.CTkLabel(
                    self,
                    text="At least one lowercase letter",
                    fg_color=("white", "gray75"),
                    corner_radius=8,
                    text_color="black",
                    height=20,
                    anchor="w",
                ),
                ctk.CTkLabel(self, text="❌", text_color="red", height=label_height),
            ],
            "digit": [
                ctk.CTkLabel(
                    self,
                    text="At least one digit",
                    fg_color=("white", "gray75"),
                    corner_radius=8,
                    text_color="black",
                    height=20,
                    anchor="w",
                ),
                ctk.CTkLabel(self, text="❌", text_color="red", height=label_height),
            ],
            "special": [
                ctk.CTkLabel(
                    self,
                    text="At least one special character",
                    fg_color=("white", "gray75"),
                    corner_radius=8,
                    text_color="black",
                    height=20,
                    anchor="w",
                ),
                ctk.CTkLabel(self, text="❌", text_color="red", height=label_height),
            ],
        }

        self.passwordEntryEncryption = ctk.CTkEntry(
            self,
            placeholder_text="Enter password:",
            show="*",
            height=30,
            font=("", 13),
        )
        self.passwordEntryEncryption.grid(
            row=1, column=1, columnspan=4, padx=0, pady=(0, 30), sticky="ew"
        )
        self.passwordEntryEncryption.bind("<KeyRelease>", check_password)

        for i, label in enumerate(requirements.values(), start=1):
            label[0].grid(
                row=i + 1, column=2, columnspan=3, padx=(0, 10), pady=3, sticky="ew"
            )
            label[1].grid(row=i + 1, column=1, pady=3, sticky="ew")

        self.encryptButton = ctk.CTkButton(
            self, text="Encrypt Device", command=encryption_process
        )
        self.encryptButton.grid(row=7, column=1, columnspan=4, padx=0, pady=30, sticky="ew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(9, weight=1)

        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(5, weight=1)

class TopDecryption(ctk.CTkToplevel):
    def __init__(self, parent, device):
        super().__init__(parent)
        self.device = device
        self.title(f"Decryption of {self.device}")
        self.geometry("400x300")

        self.after(250, lambda: self.iconbitmap("images/logo_color.ico"))
        self.resizable(False, False)

        def update_progress(processed_files, total_files):
            progress = processed_files / total_files
            self.progressBar.set(progress)
            self.progressLabel.configure(text=f"{progress*100:.2f}%")

        def decryption_process():
            password = self.passwordEntryDecryption.get()

            def run_decryption():
                try:
                    DeviceEncryption.decryptDirectory(
                        self.device, password, update_progress
                    )
                    messagebox.showinfo("Success", "Decryption completed!")

                except ValueError as e:
                    messagebox.showerror("Error", f"{str(e)}, try again!")
                    self.passwordEntryDecryption.delete(0, "end")

            decryption_thread = threading.Thread(target=run_decryption)
            decryption_thread.start()
            self.after(500, check_if_running, decryption_thread, self)

        def check_if_running(thread, window):
            if thread.is_alive():
                window.after(500, check_if_running, thread, window)
            else:
                window.destroy()
                window.update()

        self.passwordEntryDecryption = ctk.CTkEntry(
            self,
            placeholder_text="Enter password:",
            show="*",
            height=30,
            font=("", 13),
        )
        self.passwordEntryDecryption.grid(
            row=1, column=1, columnspan=4, padx=0, pady=(20, 0), sticky="ew"
        )

        self.decryptButton = ctk.CTkButton(
            self, text="Decrypt Device", command=decryption_process
        )
        self.decryptButton.grid(row=2, column=1, columnspan=4, padx=0, pady=20, sticky="ew")

        self.progressBar = ctk.CTkProgressBar(
            self, width=200, height=15, progress_color="green"
        )
        self.progressBar.set(0)
        self.progressBar.grid(row=3, column=1, columnspan=3, padx=0, sticky="ew")
        self.progressLabel = ctk.CTkLabel(self, text="0%", text_color="white")
        self.progressLabel.grid(row=3, column=4, padx=(10, 0))

        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(5, weight=1)

class MainApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.width = 500
        self.height = 350
        self.centerScreen()

        self.title("EncryptMe")
        self.resizable(False, False)

        self.iconbitmap("images/logo_color.ico")

        self.photo = add_corners(Image.open("images/leftPanel.png"), 15)
        self.photo = ctk.CTkImage(self.photo, size=(158, 318))

        self.leftPanel = ctk.CTkLabel(self, image=self.photo, text="")
        self.leftPanel.grid(row=0, column=0, rowspan=6, padx=20, pady=20, sticky="nsew")

        self.ScanButton = ctk.CTkButton(
            self,
            text="Scan for Devices!",
            command=self.recognizeDrives,
        )
        self.ScanButton.grid(row=1, column=1, padx=0, pady=10)

        self.Dropdown = ctk.CTkOptionMenu(self, values=["No devices found"])
        self.Dropdown.grid(row=2, column=1, padx=0, pady=10)
        self.Dropdown.set("...")

        self.EncryptButton = ctk.CTkButton(
            self,
            text="Encrypt",
            command=self.open_encryption_window,
        )
        self.EncryptButton.grid(row=3, column=1, padx=0, pady=10)
        self.DecryptButton = ctk.CTkButton(
            self,
            text="Decrypt",
            command=self.open_decryption_window,
        )
        self.DecryptButton.grid(row=4, column=1, padx=0, pady=10)

        self.top_window_encryption = None
        self.top_window_decryption = None

        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(5, weight=1)
        self.grid_columnconfigure(1, weight=1)

    def open_encryption_window(self):
        if self.Dropdown.get() in ["Select a device", "...", "No devices found"]:
            messagebox.showerror("Error", "Please select a valid device to encrypt!")
            return
        encrypted_data = os.path.join(self.Dropdown.get(), "encrypted_data.aes")
        if os.path.exists(encrypted_data):
            messagebox.showerror("Error", "This device is already encrypted!")
            return
        
        if self.top_window_encryption is None or not self.top_window_encryption.winfo_exists():
            self.top_window_encryption = TopEncryption(self, self.Dropdown.get())    
        else:
            self.top_window_encryption.deiconify()
            self.top_window_encryption.focus()

    def open_decryption_window(self):
        if self.Dropdown.get() in ["Select a device", "...", "No devices found"]:
            messagebox.showerror("Error", "Please select a valid device to decrypt!")
            return

        encrypted_data = os.path.join(self.Dropdown.get(), "encrypted_data.aes")
        if not os.path.exists(encrypted_data):
            messagebox.showerror("Error", "This device is not encrypted!")
            return

        if self.top_window_decryption is None or not self.top_window_decryption.winfo_exists():
            self.top_window_decryption = TopDecryption(self, self.Dropdown.get())
        else:
            self.top_window_decryption.deiconify()
            self.top_window_decryption.focus()

    def centerScreen(self):
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        scaling = self._get_window_scaling()

        x = int(((screen_width / 2) - (self.width / 2)) * scaling)
        y = int(((screen_height / 2) - (self.height / 2)) * scaling)

        self.geometry(f"{self.width}x{self.height}+{x}+{y}")

    def recognizeDrives(self):
        drives = []
        for drive in psutil.disk_partitions():
            if "removable" in drive.opts:
                drives.append(drive.device)

        if drives:
            self.Dropdown.configure(values=drives)
            self.Dropdown.set("Select a device")
        else:
            self.Dropdown.set("No devices found")


def add_corners(im, rad):
    circle = Image.new("L", (rad * 2, rad * 2), 0)
    draw = ImageDraw.Draw(circle)
    draw.ellipse((0, 0, rad * 2 - 1, rad * 2 - 1), fill=255)
    alpha = Image.new("L", im.size, 255)
    w, h = im.size
    alpha.paste(circle.crop((0, 0, rad, rad)), (0, 0))
    alpha.paste(circle.crop((0, rad, rad, rad * 2)), (0, h - rad))
    alpha.paste(circle.crop((rad, 0, rad * 2, rad)), (w - rad, 0))
    alpha.paste(circle.crop((rad, rad, rad * 2, rad * 2)), (w - rad, h - rad))
    im.putalpha(alpha)
    return im


if __name__ == "__main__":
    app = MainApp()
    app.mainloop()
