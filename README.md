# Secure File Transfer System

The Secure File Transfer System is a web application that provides cryptographic functionalities for secure file transfer between users. The system employs a combination of asymmetric and symmetric encryption, digital signatures, and key management to ensure the confidentiality and integrity of transferred files.

## Notice

- The .txt file you want to process must be in the project directory.
- If you don't have an asymmetric key pair, don't worry, it is automatically generated before the encryption process !
- Don't forget to read the [Disclaimer](#disclaimer) section. And if you have any questions, please contact me.
- Signature and signature_and_encryption, you must select asymmetric_encrypted during decryption. This is how the sequence works.

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
  - [Setting Up Environment Variables](#setting-up-environment-variables)
- [Project Structure](#project-structure)
- [Source Code Examples](#source-code-examples)
  - [Asymmetric Functions](#asymmetric-functions)
  - [Symmetric Functions](#symmetric-functions)
- [Web Application Usage](#web-application-usage)
  - [Generating Keys](#generating-keys)
  - [File Encryption and Signing](#file-encryption-and-signing)
  - [File Decryption and Verification](#file-decryption-and-verification)

## Introduction

The Secure File Transfer System allows users to securely transfer files through a web interface. It utilizes asymmetric key pairs for user authentication and file signing, as well as symmetric encryption for file confidentiality during transfer.

1. **Key Generation:**

   - Users can generate their key pairs for secure communication.

2. **File Encryption:**

   - Files can be encrypted symmetrically or asymmetrically based on user preferences.

3. **File Signing:**

   - Users can sign files to ensure the integrity and authenticity of the transferred data.

4. **File Decryption:**

   - Encrypted files can be decrypted using the appropriate keys.

5. **Verification:**
   - Signature verification ensures that files have not been tampered with during transfer.

## Installation

Follow these steps to set up and run the Secure File Transfer System locally:

```bash
# Clone the repository
git clone https://github.com/alperengokbak/Asymmetric-Symmetric-Encryption.git

# Run the application
python app.py
```

### Setting Up Environment Variables

Create a `.env` file in the project root with the following variables:

```env
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your_secret_key
```

## Project Structure

The project is structured as follows:

```bash
.
├── func
│   ├── asymmetric_functions.py
│   └── symmetric_functions.py
├── templates
│   └── index.html
├── .env
├── app.py
└── test.txt
```

## Source Code Examples

### Asymmetric Functions

#### Signing Data

```python
# func/asymmetric_functions.py

def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_key_and_encrypt(input_file, output_file, receiver_public_key, private_key):
    # Read the plaintext file
    with open(input_file, 'rb') as file:
        plaintext = file.read()

    # Generate the shared key
    shared_key = generate_shared_key(private_key, receiver_public_key)

    # Derive a key from the shared key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'secret key',
    ).derive(shared_key)

    # Use the symmetric key to encrypt the data
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(b'\x00' * 16))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(plaintext) + encryptor.finalize()

    # Create the directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    with open(output_file, 'wb') as file:
        file.write(encrypted_data)

def prehash_sign_data(input_file, output_file, private_key):
    # If input_file contains only the filename, join it with the appropriate directory path
    input_file_path = input_file if os.path.isabs(input_file) else os.path.join(os.getcwd(), input_file)

    with open(input_file_path, 'rb') as file:
        data = file.read()

    # Using a consistent hash algorithm
    hash_algorithm = hashes.SHA256()

    # Creating a hasher and updating it with new data
    hash_value = hashes.Hash(hash_algorithm)
    hash_value.update(data)
    hashed_data = hash_value.finalize()

    # Signing the hashed data
    signature = private_key.sign(hashed_data, ec.ECDSA(utils.Prehashed(hash_algorithm)))

    # Create the directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    with open(output_file, 'wb') as file:
        file.write(signature)

    return output_file
```

### Symmetric Functions

#### Encrypting and Decrypting Files

```python
# func/symmetric_functions.py

def createSymmetricKey() -> bytes:
    # Generates a random key using the generate_key() method of the Fernet class.
    return Fernet.generate_key()

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

def decrypt_file_symmetric(input_file_path: str, output_file_path: str, symmetric_key: bytes):
    with open(input_file_path, 'rb') as file:
        encrypted_message = file.read()
    try:
        decrypted_message = symmetric_key.decrypt(encrypted_message)
    except InvalidToken:
        return f"Invalid key for {input_file_path}"

    # Create the directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

    with open(output_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_message)

    return output_file_path
```

## Web Application Usage

### Generating Keys

1. Visit the home page of the application.

2. If you are a new user, don't worry about how to generate keys. Just enter requirements and select the action you want to take. The application will automatically generate a key pair for you with your selected action.

### File Encryption and Signing

1. Choose a file to upload.

2. Specify your username, the receiver's username, and the desired action (Sign, Encrypt, or Sign and Encrypt).

3. Click the "Upload" button.

### File Decryption and Verification

1. Upload the original file and the encrypted or signed file.

2. Specify your username, the sender's username, and the desired action (Verify, Decrypt, or Verify and Decrypt).

3. Click the "Download" button.

## Disclaimer

This application is developed for educational purposes and should not be used in production environments without proper security assessments. The security of the implemented cryptography depends on the correct usage and management of keys.

For any issues or concerns, please contact the project maintainer.
