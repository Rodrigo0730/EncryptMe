import os, sys, string 
import psutil
import customtkinter as ctk
from PIL import Image, ImageDraw
from tkinter import messagebox, filedialog, Toplevel

ctk.set_default_color_theme("styles.json")

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

        self.ScanButton = ctk.CTkButton(self, text="Scan for Devices!", command=self.recognizeDrives, border_width=1, border_color="#fffacd")
        self.ScanButton.grid(row=1, column=1, padx=0, pady=10)

        self.Dropdown = ctk.CTkOptionMenu(self, values=["No devices found"])
        self.Dropdown.grid(row=2, column=1, padx=0, pady=10)
        self.Dropdown.set("...")

        self.EncryptButton = ctk.CTkButton(self, text="Encrypt", command=self.encrypt, border_width=1, border_color="#fffacd")
        self.EncryptButton.grid(row=3, column=1, padx=0, pady=10)
        self.DecryptButton = ctk.CTkButton(self, text="Decrypt", command=self.decrypt, border_width=1, border_color="#fffacd")
        self.DecryptButton.grid(row=4, column=1, padx=0, pady=10)

        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_rowconfigure(2, weight=0)
        self.grid_rowconfigure(3, weight=0)
        self.grid_rowconfigure(4, weight=0)
        self.grid_rowconfigure(5, weight=1)
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)

    def encryptionWindow(self):
        window = ctk.CTkToplevel(self)
        window.title(f"Encryption of {self.Dropdown.get()}")
        window.geometry("400x300")

        window.after(250, lambda: window.iconbitmap("images/logo_color.ico"))
        window.resizable(False, False)

        passwordLabel = ctk.CTkLabel(window, text="Enter Password:")
        passwordLabel.grid(row=0, column=0, padx=(30, 0), pady=30)
        passwordEntry = ctk.CTkEntry(window, show="*")
        passwordEntry.grid(row=0, column=2, columnspan=2, padx=(0,30), pady=30, sticky="nsew")

        window.grid_rowconfigure(0, weight=0)
        window.grid_columnconfigure(0, weight=1)
        window.grid_columnconfigure(1, weight=0)
        window.grid_columnconfigure(2, weight=1)

    def encrypt(self):
        if self.Dropdown.get() in ["Select a device", "...", "No devices found"]:
            messagebox.showerror("Error", "Please select a valid device to encrypt!")
            return
        
        self.encryptionWindow()
        


    def decrypt(self):
        if self.Dropdown.get() in ["Select a device", "...", "No devices found"]:
            messagebox.showerror("Error", "Please select a valid device to decrypt!")
            return
        
        encrypted_data = os.path.join(self.Dropdown.get(), "encrypted_data.aes")
        if not os.path.exists(encrypted_data):
            messagebox.showerror("Error", "This device is not encrypted!")
            return

        

    def centerScreen(self):
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()   
        scaling = self._get_window_scaling()

        x = int(((screen_width/2) - (self.width/2)) * scaling)
        y = int(((screen_height/2) - (self.height/2)) * scaling)
    
        self.geometry(f"{self.width}x{self.height}+{x}+{y}")

    def recognizeDrives(self):
        drives = []
        for drive in psutil.disk_partitions():
            if 'removable' in drive.opts:
                drives.append(drive.device)
        
        if drives:
            self.Dropdown.configure(values=drives)
            self.Dropdown.set("Select a device")
        else:
            self.Dropdown.set("No devices found")

def add_corners(im, rad):
    circle = Image.new('L', (rad * 2, rad * 2), 0)
    draw = ImageDraw.Draw(circle)
    draw.ellipse((0, 0, rad * 2 - 1, rad * 2 - 1), fill=255)
    alpha = Image.new('L', im.size, 255)
    w, h = im.size
    alpha.paste(circle.crop((0, 0, rad, rad)), (0, 0))
    alpha.paste(circle.crop((0, rad, rad, rad * 2)), (0, h - rad))
    alpha.paste(circle.crop((rad, 0, rad * 2, rad)), (w - rad, 0))
    alpha.paste(circle.crop((rad, rad, rad * 2, rad * 2)), (w - rad, h - rad))
    im.putalpha(alpha)
    return im
 
app = MainApp()
app.mainloop()


