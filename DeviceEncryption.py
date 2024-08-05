from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import Chaoskey as ck
import os
import psutil
import hashlib


class AES:
    def __init__(self, password, key_file=None):
        self.check_password_requirements(password)
        if isinstance(password, str):
            self.password = password.encode("utf-8")
        else:
            self.password = password
        self.key = None

        if key_file:
            self.load_key_from_file(key_file)
        else:
            self.key = self._derive_aes_key()

    def _derive_aes_key(self):
        try:
            # Generate a random 256-bit key using PBKDF2HMAC with a PRNG generated salt
            prng = ck.PRNG()
            salt = prng.generate_key(self.password, 16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=1000000,
                backend=default_backend(),
            )
            return kdf.derive(self.password)
        except Exception as e:
            raise ValueError("Error deriving AES key: {}".format(e))

    def _get_aes_key(self):
        if self.key is None:
            self.key = self._derive_aes_key()
        return self.key

    def save_key_to_file(self, key_file):
        try:
            with open(key_file, "wb") as f:
                key = self._get_aes_key()
                f.write(key)
        except Exception as e:
            raise ValueError("Error saving key to file: {}".format(e))

    def load_key_from_file(self, key_file):
        try:
            with open(key_file, "rb") as f:
                self.key = f.read()
        except Exception as e:
            raise ValueError("Error loading key from file: {}".format(e))

    def encrypt(self, data):
        prng = ck.PRNG()
        iv = prng.generate_key(self.password, 12)
        key = self._get_aes_key()
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        encrypted_data_with_tag = encrypted_data + encryptor.tag
        return iv, encrypted_data_with_tag

    def decrypt(self, iv, encrypted_data_with_tag):
        encrypted_data = encrypted_data_with_tag[:-16]
        tag = encrypted_data_with_tag[-16:]
        cipher = Cipher(
            algorithms.AES(self._get_aes_key()),
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
        aes = AES(password)
        device = directory
        outputFilePath = os.path.join(device, "encrypted_data.aes")
        data = {}

        total_files = sum(len(files) for _, _, files in os.walk(device))
        processed_files = 0

        for root, dirs, files in os.walk(device):
            for file in files:
                inputFilePath = os.path.join(root, file)
                relativePath = os.path.relpath(inputFilePath, device)

                with open(inputFilePath, "rb") as f:
                    data[relativePath] = f.read()
                
                processed_files += 1
                if progress_callback:
                    progress = (processed_files / total_files) * 100
                    progress_callback(progress)

        all_data = "\n".join(
            f"{path}:{content.hex()}" for path, content in data.items()
        ).encode()
        hashed_data = hashlib.sha256(all_data).hexdigest()
        data_with_hash = f"{hashed_data}\n".encode() + all_data

        iv, encrypted_data_with_tag = aes.encrypt(data_with_hash)

        with open(outputFilePath, "wb") as f:
            f.write(iv + encrypted_data_with_tag)
            f.flush()
            os.fsync(f.fileno())

        for root, _, files in os.walk(device):
            for file in files:
                inputFilePath = os.path.join(root, file)
                if inputFilePath == outputFilePath:
                    continue
                else:
                    os.remove(inputFilePath)
        for root, dirs, _ in os.walk(device, topdown=False):
            for dir in dirs:
                os.rmdir(os.path.join(root, dir))
    except ValueError as e:
        print(e)


def decryptDirectory(password):
    aes = AES(password)
    device = recognize_drives()[0]
    inputFilePath = os.path.join(device, "encrypted_data.aes")
    outputDirectory = device

    with open(inputFilePath, "rb") as f:
        iv = f.read(12)
        encrypted_data_with_tag = f.read()

    try:
        data_with_hash = aes.decrypt(iv, encrypted_data_with_tag)
    except Exception:
        print("Password is incorrect")
        return

    stored_hash, data = data_with_hash.decode().split("\n", 1)
    hash = hashlib.sha256(data.encode()).hexdigest()

    if stored_hash != hash:
        print("Hash mismatch")
        return

    for entry in data.split("\n"):
        relativePath, content = entry.split(":", 1)
        outputFilePath = os.path.join(outputDirectory, relativePath)

        os.makedirs(os.path.dirname(outputFilePath), exist_ok=True)
        with open(outputFilePath, "wb") as f:
            f.write(bytes.fromhex(content))

    print("Decryption completed successfully")

    os.remove(inputFilePath)


def main():
    decryptDirectory("Password1:")


if __name__ == "__main__":
    main()
