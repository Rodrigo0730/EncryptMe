# EncryptMe

## Overview

This Windows APP provides functionality for encrypting and decrypting files on a removable drive using AES (Advanced Encryption Standard) encryption. It ensures that the files on the drive are securely encrypted and can be decrypted only with the correct password. 

## Features

- **AES Encryption and Decryption**: Uses AES encryption in GCM mode for secure encryption and decryption of data.
- **Password Requirements**: Enforces strong password policies to ensure security.
- **Key Management**: Supports key derivation using PBKDF2HMAC.
- **File Handling**: Encrypts all files in a specified directory and removes the original files after encryption. Decrypts and restores files from an encrypted archive.
- **Drive Recognition**: Identifies removable drives for file operations.
- **Chaos-based PRNG**: Utilizes a chaos-based PRNG (Pseudo-Random Number Generator) for generating initialization vectors (IV) and salts for a safe key generation.

## TO-DO
- Create the user interface
- Add password check in decryption, not just raising an error for error during decryption
- Concern about time it takes to encrypt larger files, maybe add a percentage bar in the ui while encrypting or do some research about how to predict how much time it will take.
- Add functionality to once a device is encrypted, if it is opened in whichever device to open a window requesting the password, if the password is correct, decrypt the files and let the user once its finished with using the data in the device to encrypt the device again for correct removal.
