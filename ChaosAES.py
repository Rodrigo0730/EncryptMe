from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib, getpass, os
import Chaoskey as ck

class AES:
    def __init__(self, password, key_file=None):
        if isinstance(password, str):
            self.password = password.encode('utf-8')
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
            salt = prng.generate_key(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=1000000,
                backend=default_backend()
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
        iv = prng.generate_key(12)
        key = self._get_aes_key()
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        encrypted_data_with_tag = encrypted_data + encryptor.tag
        return iv, encrypted_data_with_tag
    
    def decrypt(self, iv, encrypted_data_with_tag):
        encrypted_data = encrypted_data_with_tag[:-16]
        tag = encrypted_data_with_tag[-16:]
        cipher = Cipher(algorithms.AES(self._get_aes_key()), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted_data
    
    def encryptString(self, text):
        key = self._get_aes_key()
        prng = ck.PRNG()
        iv = prng.generate_key(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(text.encode('utf-8')) + encryptor.finalize()
        encrypted_data_with_tag = encrypted_data + encryptor.tag
        return iv, encrypted_data_with_tag

    def decryptString(aes, iv, encrypted_data_with_tag):
        key = aes._get_aes_key()
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, encrypted_data_with_tag[-16:]), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data_with_tag[:-16]) + decryptor.finalize()
        return decrypted_data.decode('utf-8')
    


"""
class AESKeySecurityTester:
    def __init__(self, passphrase, pw):
        self.passphrase = passphrase.encode('utf-8')
        self.pw = pw

    def test_key_security(self, num_tests=1000):
        aes_cryptor = AES(self.passphrase, self.pw)

        try:
            key_entropy = self._calculate_key_entropy(aes_cryptor._get_aes_key())
            print("Key Entropy:", key_entropy)
        except Exception as e:
            print("Error calculating key entropy: {}".format(e))

        try:
            self._test_encryption_security(aes_cryptor, num_tests)
        except Exception as e:
            print("Error testing encryption security: {}".format(e))

    def _calculate_key_entropy(self, key):
        # Calculate the key's entropy (assuming the key is in bytes format)
        unique_bytes = len(set(key))
        total_bytes = len(key)

        entropy = (unique_bytes / total_bytes * 8)
        return entropy

    def _test_encryption_security(self, aes_cryptor, num_tests):
        # Perform encryption and decryption tests
        for _ in range(num_tests):
            data_to_encrypt = os.urandom(32)  # Random data to encrypt (32 bytes)
            iv, encrypted_data = aes_cryptor.encrypt(data_to_encrypt)
            decrypted_data = aes_cryptor.decrypt(iv, encrypted_data)

            if decrypted_data != data_to_encrypt:
                print("Encryption and Decryption mismatch!")
                return

        print("All encryption and decryption tests passed successfully.")

    @staticmethod
    def check_password_requirements(password):
        min_length = 8
        requires_uppercase = True
        requires_lowercase = True
        requires_digit = True
        requires_special_char = True

        conditions_not_met = []

        if len(password) < min_length:
            conditions_not_met.append(f"Password should be at least {min_length} characters long.")

        if requires_uppercase and not any(char.isupper() for char in password):
            conditions_not_met.append("Password should contain at least one uppercase character.")

        if requires_lowercase and not any(char.islower() for char in password):
            conditions_not_met.append("Password should contain at least one lowercase character.")

        if requires_digit and not any(char.isdigit() for char in password):
            conditions_not_met.append("Password should contain at least one digit.")

        special_chars = r"!@#$%^&*()_-+={}[]|\:;\"'<>,.?/~"
        if requires_special_char and not any(char in special_chars for char in password):
            conditions_not_met.append("Password should contain at least one special character.")

        if conditions_not_met:
            if len(password) > 0:
                print("Password requirements not met:")
                for condition in conditions_not_met:
                    print(condition)
            return False
        else:
            return True
        
"""