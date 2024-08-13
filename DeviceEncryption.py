import hashlib
import os
import struct
import zlib

import psutil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import chaosrandom


class AES:
    def __init__(self, password, salt=None):
        self.key = None
        self.salt = salt
        self.password = (
            password.encode("utf-8") if isinstance(password, str) else password
        )

        if self.salt is None:
            self.check_password_requirements(password)
            self.salt = self._generate_salt()

        self.key = self._derive_key()

    def _generate_salt(self):
        prng = chaosrandom.PRNG()
        return prng.generate_key(16)

    def _derive_key(self):
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=1000000,
                backend=default_backend(),
            )
            return kdf.derive(self.password)
        except Exception as e:
            raise ValueError("Error deriving AES key: {}".format(e))

    def encrypt(self, data):
        prng = chaosrandom.PRNG()
        iv = prng.generate_key(12)
        key = self.key
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        encrypted_data_with_tag = iv + encryptor.tag + encrypted_data
        return encrypted_data_with_tag

    def decrypt(self, encrypted_data_with_tag):
        iv = encrypted_data_with_tag[:12]
        tag = encrypted_data_with_tag[12:28]
        encrypted_data = encrypted_data_with_tag[28:]
        key = self.key
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
        output_file_path = os.path.join(directory, "encrypted_data.aes")
        data = bytearray()
        files_to_delete, total_files = [], 0

        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if (
                    "System Volume Information"
                    not in os.path.relpath(file_path, directory)
                    and file_path != output_file_path
                ):
                    files_to_delete.append(file_path)
                    total_files += 1

        processed_files = 0
        for file_path in files_to_delete:
            relative_path = os.path.relpath(file_path, directory)

            with open(file_path, "rb") as f:
                file_data = f.read()

            compressed_data = zlib.compress(file_data)
            path_length = len(relative_path.encode("utf-8"))
            data += struct.pack(
                f"<I{path_length}sI",
                path_length,
                relative_path.encode(),
                len(compressed_data),
            )
            data += compressed_data

            os.remove(file_path)

            processed_files += 1
            if progress_callback:
                progress_callback(processed_files, total_files)

        hashed_data = hashlib.sha256(data).digest()
        data_with_hash = hashed_data + data

        encrypted_data_with_tag = aes.encrypt(data_with_hash)

        with open(output_file_path, "wb") as f:
            f.write(salt + encrypted_data_with_tag)

        dirs_to_delete = [
            os.path.join(root, dir)
            for root, dirs, files in os.walk(directory)
            for dir in dirs
            if "System Volume Information" not in dir
        ]

        for dir_path in reversed(dirs_to_delete):
            os.rmdir(dir_path)

    except ValueError as e:
        raise ValueError(f"Error: {e}")


def decryptDirectory(directory, password, progress_callback=None):
    inputFilePath = os.path.join(directory, "encrypted_data.aes")
    outputDirectory = directory

    with open(inputFilePath, "rb") as f:
        salt = f.read(16)
        encrypted_data_with_tag = f.read()
    aes = AES(password, salt=salt)

    try:
        data_with_hash = aes.decrypt(encrypted_data_with_tag)
    except Exception:
        raise ValueError("Password is incorrect")

    stored_hash = data_with_hash[:32]
    data = data_with_hash[32:]
    hash = hashlib.sha256(data).digest()

    if stored_hash != hash:
        print("Hash mismatch")
        return

    index = 0
    while index < len(data):
        if progress_callback:
            progress_callback(index, len(data))
        path_length = struct.unpack("<I", data[index : index + 4])[0]
        index += 4
        if progress_callback:
            progress_callback(index, len(data))
        relativePath = data[index : index + path_length].decode()
        index += path_length
        if progress_callback:
            progress_callback(index, len(data))
        data_length = struct.unpack("<I", data[index : index + 4])[0]
        index += 4
        if progress_callback:
            progress_callback(index, len(data))
        compressed_data = data[index : index + data_length]
        index += data_length
        if progress_callback:
            progress_callback(index, len(data))
        file_data = zlib.decompress(compressed_data)

        outputFilePath = os.path.join(outputDirectory, relativePath)

        if not os.path.exists(os.path.dirname(outputFilePath)):
            os.makedirs(os.path.dirname(outputFilePath), exist_ok=True)
        with open(outputFilePath, "wb") as f:
            f.write(file_data)

    os.remove(inputFilePath)


def main():
    directory = recognize_drives()[0]
    # encryptDirectory(directory=directory, password="Password1:")
    decryptDirectory(directory=directory, password="Password1:")


if __name__ == "__main__":
    main()
