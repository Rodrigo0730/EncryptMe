from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import chaosrandom
import os
import psutil
import hashlib
import zlib
import struct


class AES:
    def __init__(self, password, salt=None):
        self.check_password_requirements(password)
        self.password = password.encode("utf-8") if isinstance(password, str) else password

        self.key = None
        self.salt = salt

        self.key, self.salt = self._derive_key_and_salt()

    def _derive_key_and_salt(self):
        if self.salt is None:
            prng = chaosrandom.PRNG()
            salt = prng.generate_key(16)
        else:
            salt = self.salt

        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=1000000,
                backend=default_backend(),
            )
            return kdf.derive(self.password), salt
        except Exception as e:
            raise ValueError("Error deriving AES key: {}".format(e))

    def _get_aes_key(self):
        if self.key is None:
            self.key, self.salt = self._derive_aes_key()
        return self.key, self.salt

    def encrypt(self, data):
        prng = chaosrandom.PRNG()
        iv = prng.generate_key(12)
        key, _ = self._get_aes_key()
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        encrypted_data_with_tag = iv + encryptor.tag + encrypted_data
        return encrypted_data_with_tag

    def decrypt(self, encrypted_data_with_tag):
        iv = encrypted_data_with_tag[:12]
        tag = encrypted_data_with_tag[12:28]
        encrypted_data = encrypted_data_with_tag[28:]
        key, _ = self._get_aes_key()
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted_data

    @staticmethod
    def check_password_requirements(password):
        min_length = 8
        requires_uppercase = True
        requires_lowercase = True
        requires_digit = True
        requires_special_char = True

        conditions_not_met = []

        if len(password) < min_length:
            conditions_not_met.append(
                f"Password should be at least {min_length} characters long."
            )

        if requires_uppercase and not any(char.isupper() for char in password):
            conditions_not_met.append(
                "Password should contain at least one uppercase character."
            )

        if requires_lowercase and not any(char.islower() for char in password):
            conditions_not_met.append(
                "Password should contain at least one lowercase character."
            )

        if requires_digit and not any(char.isdigit() for char in password):
            conditions_not_met.append("Password should contain at least one digit.")

        special_chars = r"!@#$%^&*()_-+={}[]|\:;\"'<>,.?/~"
        if requires_special_char and not any(
            char in special_chars for char in password
        ):
            conditions_not_met.append(
                "Password should contain at least one special character."
            )

        if conditions_not_met:
            if len(password) > 0:
                print("Password requirements not met:")
                for condition in conditions_not_met:
                    print(condition)
            raise ValueError("Try again")

        return


def recognize_drives():
    drives = []
    for drive in psutil.disk_partitions():
        if "removable" in drive.opts:
            drives.append(drive.device)
    return drives


def encryptDirectory(directory, password, progress_callback=None):
    try:
        aes = AES(password, salt=None)
        salt = aes.salt
        device = directory
        outputFilePath = os.path.join(device, "encrypted_data.aes")
        data = b""

        total_files = sum(len(files) for _, _, files in os.walk(device))
        processed_files = 0

        for root, dirs, files in os.walk(device):
            for file in files:
                inputFilePath = os.path.join(root, file)
                relativePath = os.path.relpath(inputFilePath, device)

                with open(inputFilePath, "rb") as f:
                    file_data = f.read()

                if "System Volume Information" in relativePath or file.startswith('.'):
                    continue

                compressed_data = zlib.compress(file_data)
                path_length = len(relativePath.encode("utf-8"))
                data += struct.pack(f'<I{path_length}sI', path_length, relativePath.encode(), len(compressed_data))
                data += compressed_data

                processed_files += 1
                if progress_callback:
                    progress = (processed_files / total_files) * 100
                    progress_callback(progress)

        hashed_data = hashlib.sha256(data).digest()
        data_with_hash = hashed_data + data

        encrypted_data_with_tag = aes.encrypt(data_with_hash)

        with open(outputFilePath, "wb") as f:
            f.write(salt + encrypted_data_with_tag)
            f.flush()
            os.fsync(f.fileno())

        for root, _, files in os.walk(device):
            for file in files:
                inputFilePath = os.path.join(root, file)
                if inputFilePath == outputFilePath or "System Volume Information" in inputFilePath or file.startswith('.'):
                    continue
                else:
                    os.remove(inputFilePath)
        for root, dirs, _ in os.walk(device, topdown=False):
            for dir in dirs:
                if dir == "System Volume Information" or dir.startswith('.'):
                    continue
                os.rmdir(os.path.join(root, dir))
    except ValueError as e:
        print(e)


def decryptDirectory(directory, password):
    device = directory
    inputFilePath = os.path.join(device, "encrypted_data.aes")
    outputDirectory = device

    with open(inputFilePath, "rb") as f:
        salt = f.read(16)
        print(salt, type(salt))
        encrypted_data_with_tag = f.read()

    aes = AES(password, salt=salt)
    print(aes.salt == salt)

    try:
        data_with_hash = aes.decrypt(encrypted_data_with_tag)
    except Exception:
        print("Password is incorrect")
        return

    stored_hash = data_with_hash[:32]
    data = data_with_hash[32:]
    hash = hashlib.sha256(data).digest()

    if stored_hash != hash:
        print("Hash mismatch")
        return

    index = 0
    while index < len(data):
        path_length = struct.unpack("<I",data[index:index+4])[0]
        index += 4
        relativePath = data[index:index+path_length].decode()
        index += path_length
        data_length = struct.unpack("<I", data[index:index+4])[0]
        index += 4
        compressed_data = data[index:index+data_length]
        index += data_length
        file_data = zlib.decompress(compressed_data)

        outputFilePath = os.path.join(outputDirectory, relativePath)

        if not os.path.exists(os.path.dirname(outputFilePath)):
            os.makedirs(os.path.dirname(outputFilePath), exist_ok=True)
        with open(outputFilePath, "wb") as f:
            f.write(file_data)

    print("Decryption completed successfully")

    os.remove(inputFilePath)

def main():
    directory = recognize_drives()[0]
    encryptDirectory(directory=directory, password="Password1:")
    decryptDirectory(directory=directory, password="Password1:")


if __name__ == "__main__":
    main()
