from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
import os

# Generating a private key and public key pair
def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data(input_file, output_file, private_key):
    with open(input_file, 'rb') as file:
        data = file.read()

    # Using a consistent hash algorithm
    hash_algorithm = hashes.SHA256()

    # Creating a hasher and updating it with new data
    hash_value = hashes.Hash(hash_algorithm)
    hash_value.update(data)
    hashed_data = hash_value.finalize()

    # Signing the hashed data
    signature = private_key.sign(hashed_data, ec.ECDSA(hashes.SHA256()))
    
    # Create the directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    with open(output_file, 'wb') as file:
        file.write(signature)

    return output_file

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

def verify_prehashed_signature(signature, hashed_data, public_key):
    try:
        public_key.verify(signature, hashed_data, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        print("Signature verification succeeded.")
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

def verify_signature(original_file, signature_file, sender_public_key):
    # Read the data from the input file
    data = original_file.read()

    # Read the signature from the signature file
    with open(signature_file, 'rb') as sig_file:
        signature = sig_file.read()

    # Using a consistent hash algorithm
    hash_algorithm = hashes.SHA256()

    # Creating a hasher and updating it with new data
    hash_value = hashes.Hash(hash_algorithm)
    hash_value.update(data)
    hashed_data = hash_value.finalize()

    # Verify the signature
    try:
        sender_public_key.verify(signature, hashed_data, ec.ECDSA(hashes.SHA256()))
        return True  # Signature is valid
    except InvalidSignature:
        return False  # Signature is invalid

def generate_shared_key(private_key, public_key):
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    return shared_key

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
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(os.urandom(16)))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(plaintext) + encryptor.finalize()

    # Create the directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    with open(output_file, 'wb') as file:
        file.write(encrypted_data)

def derive_key_and_decrypt(input_file, output_file, sender_public_key, private_key):
    # Read the encrypted data
    with open(input_file, 'rb') as file:
        encrypted_data = file.read()

    # Generate the shared key
    shared_key = generate_shared_key(private_key, sender_public_key)

    # Derive the key from the shared key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'secret key',
    ).derive(shared_key)

    # Use the derived key to decrypt the data
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(os.urandom(16)))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Create the directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    # Write the decrypted data to the output file
    with open(output_file, 'wb') as file:
        file.write(decrypted_data)
    
    return output_file

# Function to save ECC private key to file
def save_private_key(private_key, filename):
    with open(filename, 'wb') as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
                #encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
            )
        )

# Function to save ECC public key to file
def save_public_key(public_key, filename):
    with open(filename, 'wb') as key_file:
        key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# Function to load ECC private key from file
def load_private_key(filename):
    with open(filename, 'rb') as key_file: # Open the key file for reading. (Binary mode is required.)
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key

# Function to load ECC public key from file
def load_public_key(filename):
    with open(filename, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key