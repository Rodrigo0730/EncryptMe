import ChaosAES as CAES
import Chaoskey as ck
from pathlib import Path
import os
import psutil

def encryptFilename(aes, filename):
    iv, encrypted_data_with_tag = aes.encryptString(filename)
    return iv.hex() + encrypted_data_with_tag.hex()

def decryptFilename(aes, encrypted_filename):
    iv = bytes.fromhex(encrypted_filename[:24])
    encrypted_data_with_tag = bytes.fromhex(encrypted_filename[24:])
    return aes.decryptString(iv, encrypted_data_with_tag)

def encryptDirectory(aes, inputDirectory, outputDirectory):
    for root, dirs, files in os.walk(inputDirectory):
        for file in files:
            inputFilePath = os.path.join(root, file)
            relativePath = os.path.relpath(inputFilePath, inputDirectory)
            
            encrypted_filename = encryptFilename(aes, relativePath)
            outputFilePath = os.path.join(outputDirectory, encrypted_filename)

            # Skip files in the output directory
            if outputDirectory in inputFilePath:
                continue

            os.makedirs(os.path.dirname(outputFilePath), exist_ok=True)

            try:
                with open(inputFilePath, 'rb') as f:
                    data = f.read()
                iv, encrypted_data_with_tag = aes.encrypt(data)
                with open(outputFilePath, 'wb') as f:
                    f.write(iv + encrypted_data_with_tag)
            except Exception as e:
                print(f"Failed to encrypt {inputFilePath}: {e}")

def decryptDirectory(aes, inputDirectory, outputDirectory):
    for root, dirs, files in os.walk(inputDirectory):
        for file in files:
            inputFilePath = os.path.join(root, file)
            relativePath = os.path.relpath(inputFilePath, inputDirectory)
            
            decrypted_filename = decryptFilename(aes, relativePath)
            outputFilePath = os.path.join(outputDirectory, decrypted_filename)

            # Skip files in the output directory
            if outputDirectory in inputFilePath:
                continue

            os.makedirs(os.path.dirname(outputFilePath), exist_ok=True)

            try:
                with open(inputFilePath, 'rb') as f:
                    iv = f.read(12)
                    encrypted_data_with_tag = f.read()
                decrypted_data = aes.decrypt(iv, encrypted_data_with_tag)
                with open(outputFilePath, 'wb') as f:
                    f.write(decrypted_data)
            except Exception as e:
                print(f"Failed to decrypt {inputFilePath}: {e}")



def recognizeDrives():
    drives = []
    for drive in psutil.disk_partitions():
        if 'removable' in drive.opts:
            drives.append(drive.device)
    return drives

def main():
    drives = recognizeDrives()
    if not drives:
        print("no removable drives")
        return
    
    selected_drive = drives[0]   
    print(f"Found removable drive: {selected_drive}") 

    passphrase = "my_secure_passphrase"

    # Create an AES object
    aes = CAES.AES(passphrase)

    # Define the directories
    input_dir = selected_drive
    encrypted_dir = os.path.join(selected_drive, "encrypted")    
    decrypted_dir = os.path.join(selected_drive, "decrypted")

    # Encrypt the directory
    encryptDirectory(aes, input_dir, encrypted_dir)
    print("Encryption complete.")

    # Decrypt the directory
    decryptDirectory(aes, encrypted_dir, decrypted_dir)
    print("Decryption complete.")

if __name__ == "__main__":
    main()
