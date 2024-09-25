
# EncryptMe

EncryptMe is a user-friendly Windows application designed to provide robust encryption and decryption for your external drives. Utilizing AES encryption in GCM mode, EncryptMe ensures that your files are securely encrypted and can only be decrypted with the correct password to ensure your data remains secure. The application enforces strong password policies and supports key derivation using PBKDF2HMAC for enhanced security.

![Main interface of EncryptMe](images_readme/main.png)

## Prerequisites

- Python 3.11 or higher
- Required python packages from requirements.txt

## Installation

1. Install EncryptMe on your Windows machine:
    ```sh
        git clone https://github.com/Rodrigo0730/EncryptMe.git
        cd EncryptMe
    ```

2. Create a virtual env for a local installation:
    ```sh
        python -m venv env
        source env/Scripts/activate
    ```

3. Install required packages:
    ```sh
        pip install -r requirements.txt
    ```

4. Run the application:
    ```sh
        python main.py
    ```
## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](./LICENSE) file for details.

    
