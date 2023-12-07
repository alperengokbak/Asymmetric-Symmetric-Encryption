from cryptography.fernet import Fernet, MultiFernet, InvalidToken
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    
# Generates a random key using the generate_key() method of the Fernet class.
def createSymmetricKeyWithPassword(my_password, salt_size) -> Fernet:    
    # Convert to type bytes
    password = my_password.encode("utf-8")

    # Generates a 16-byte salt using os.urandom()
    salt = os.urandom(salt_size)

    # Generates a 32-byte key using PBKDF2HMAC
    kdf = PBKDF2HMAC(
      algorithm=hashes.SHA256(),
      length=32,
      salt=salt,
      iterations=480000,
    )

    # Generates a 32-byte key using PBKDF2HMAC
    key = base64.urlsafe_b64encode(kdf.derive(password))

    # Create a Fernet key object
    fernet_key = Fernet(key)

    return fernet_key

def createSymmetricKey() -> bytes:
    # Generates a random key using the generate_key() method of the Fernet class.
    return Fernet.generate_key()

def createMultiSymmetricKey(*keys: bytes) -> bytes:
    if all(isinstance(key, Fernet) for key in keys):
      return MultiFernet(keys)
    else:
      return None

def encrypt_file_symmetric(input_file_path: str, output_file_path: str, symmetric_key: bytes):
    with open(input_file_path, 'rb') as file:
        message = file.read()

    symmetric_key = Fernet(symmetric_key)
    # Encrypt the message using the Fernet key
    encrypted_message = symmetric_key.encrypt(message)

    # Create the directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

    with open(output_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_message)
    
    return output_file_path

def decrypt_file_symmetric(input_file_path: str, output_file_path: str, symmetric_key: bytes, original_file):
    with open(input_file_path, 'rb') as file:
        encrypted_message = file.read()
    
    try:
        real_data = original_file.read()
    except AttributeError:
        real_data = None

    try:
        decrypted_message = symmetric_key.decrypt(encrypted_message)
    except InvalidToken:
        return f"Invalid key for {input_file_path}"
    
    
    # Create the directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

    with open(output_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_message)

    if decrypted_message == real_data:
        return output_file_path

    return False

def timestampMessage(encrypted_message: bytes, key: bytes) -> bytes:
    # Creates a Fernet cipher object (f) using the generated key.
    return key.extract_timestamp(encrypted_message)

def saveSymmetricKey(key: Fernet, filename: str):
    # Saves the key to a file
    with open(filename, "wb") as file:
        file.write(key)

def loadSymmetricKey(filename: str) -> Fernet:
    # Loads the key from the file
    with open(filename, "rb") as file:
        key_bytes = file.read()

    # Converts the key to a Fernet object and returns it
    new_key = Fernet(key_bytes)

    return new_key