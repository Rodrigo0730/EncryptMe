import os, sys, string 
import psutil
import customtkinter as ctk
from PIL import Image, ImageTk

ctk.set_appearance_mode("light")

class App(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.width = 400
        self.height = 300
        self.centerScreen()

        self.title("USB Device Encryption Manager")
        self.resizable(False, False)

        self.logo = Image.open("env/images/logo_color.png")
        self.photo = ctk.CTkImage(self.logo, size=(125, 125))

        self.TopFrame = ctk.CTkFrame(self)
        self.TopFrame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.TopFrame.grid_columnconfigure(0, weight=1)
        self.TopFrame.grid_columnconfigure(1, weight=0)

        self.welcomeLabel = ctk.CTkLabel(self.TopFrame, text="Welcome to\nUSB Device\nEncryption Manager")
        self.welcomeLabel.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        # Place the image label on the right side of the window
        self.Image = ctk.CTkLabel(self, image=self.photo, text="")
        self.Image.grid(row=0, column=1, padx=10, pady=10, sticky="e")

        self.ScanButton = ctk.CTkButton(self, text="Scan!", command=self.recognizeDrives)
        self.ScanButton.grid(row=1, column=0, columnspan=2, pady=10)

        self.ScanResult = ctk.CTkLabel(self, text="")
        self.ScanResult.grid(row=2, column=0, columnspan=2, pady=10)

        self.grid_columnconfigure(0, weight=1)

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
            result_text = f"Found removable drives: {', '.join(drives)}"
        else:
            result_text = "No removable drives found"

        self.ScanResult.configure(text=result_text)




app = App()
app.mainloop()


