from flask import Flask, render_template, request, redirect
from func.asymmetric_functions import generate_key_pair, sign_data, prehash_sign_data, verify_signature, derive_key_and_encrypt, derive_key_and_decrypt, save_private_key, save_public_key, load_private_key, load_public_key
from func.symmetric_functions import createSymmetricKey, encrypt_file_symmetric, decrypt_file_symmetric, saveSymmetricKey, loadSymmetricKey
import os

app = Flask(__name__)

# Base directory for storing user keys
KEYS_BASE_DIR = './'

def encrypt_symmetric(receiver_keys_dir, file):
    # Encrypt the file symmetrically
    symmetric_key = createSymmetricKey()
        
    # Save the symmetric key in the user's directory
    symmetric_key_path = os.path.join(receiver_keys_dir, 'symmetric_key.pem')
    saveSymmetricKey(symmetric_key, symmetric_key_path)

    # Encrypt the file using the symmetric key
    encrypt_file_symmetric(file.filename, os.path.join(os.path.join(receiver_keys_dir, 'received'), 'symmetric_encrypted_' + file.filename), symmetric_key)

    return os.path.join(os.path.join(receiver_keys_dir, 'received'), 'symmetric_encrypted_' + file.filename)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_keys/<username>')
def generate_keys(username):
    # Generate key pair for the user if not already generated
    path = os.path.join(KEYS_BASE_DIR, "./users")
    user_keys_dir = os.path.join(path, username)

    if not os.path.exists(user_keys_dir):
        os.makedirs(user_keys_dir)

        private_key, public_key = generate_key_pair()

        private_key_path = os.path.join(user_keys_dir, 'private_key.pem')
        public_key_path = os.path.join(user_keys_dir, 'public_key.pem')

        save_private_key(private_key, private_key_path)
        save_public_key(public_key, public_key_path)

        return f"Key pair generated for {username} in directory {user_keys_dir}"
    else:
        return f"Key pair already exists for {username} in directory {user_keys_dir}"

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files or 'username' not in request.form or 'action' not in request.form:
        return "Invalid request"

    file = request.files['file']
    username = request.form['username']
    receiver_username = request.form['receiver']
    action = request.form['action']

    generate_keys(username)
    generate_keys(receiver_username)

    if file.filename == '' or username == '' or receiver_username == '' or action not in ['sign', 'encrypt', 'sign_and_encrypt']:
        return "Invalid parameters"

    # Get the user's public key and private key
    user_keys_dir = os.path.join(KEYS_BASE_DIR + "./users", username)
    private_key_path = os.path.join(user_keys_dir, 'private_key.pem')

    receiver_keys_dir = os.path.join(KEYS_BASE_DIR + "./users", receiver_username)
    receiver_public_key_path = os.path.join(receiver_keys_dir, 'public_key.pem')

    if not os.path.exists(private_key_path):
        return f"Key pair not generated for {username}. Please generate keys first."
    if not os.path.exists(receiver_public_key_path):
        return f"Key pair not generated for {receiver_username}. Please generate keys first."
        
    user_private_key = load_private_key(private_key_path)
    receiver_public_key = load_public_key(receiver_public_key_path)

    if action == 'sign':
        # Sign and save the file
        signed_file_path = prehash_sign_data(file.filename, os.path.join(os.path.join(receiver_keys_dir, 'received'), 'signed_' + file.filename), user_private_key)
        
        # Encrypt the signed file using the recipient's public key
        derive_key_and_encrypt(signed_file_path , os.path.join(os.path.join(receiver_keys_dir, 'received'), 'asymmetric_encrypted_' + file.filename), receiver_public_key, user_private_key)

    elif action == 'encrypt':
        encrypt_symmetric(receiver_keys_dir, file)

    elif action == 'sign_and_encrypt':
        # Encrypt the file symmetrically
        encrypted_file_path = encrypt_symmetric(receiver_keys_dir, file)

        # Sign and save the file
        signed_file_path = prehash_sign_data(encrypted_file_path, os.path.join(os.path.join(receiver_keys_dir, 'received'), 'signed_' + file.filename), user_private_key)

        # Encrypt the signed file using the recipient's public key
        derive_key_and_encrypt(signed_file_path, os.path.join(os.path.join(receiver_keys_dir, 'received'), 'asymmetric_encrypted_' + file.filename), receiver_public_key, user_private_key)

    return render_template('index.html')

@app.route('/download', methods=['POST'])
def download():
    if 'file_decrypt' not in request.files or 'username_decrypt' not in request.form or 'action_decrypt' not in request.form:
        return "Invalid request"
    
    file = request.files['file_decrypt']
    original_file = request.files['original_file']
    username = request.form['username_decrypt']
    sender_username = request.form['sender']
    action = request.form['action_decrypt']

    if file.filename == '' or original_file.filename == '' or sender_username == '' or username == '' or action not in ['verify', 'decrypt', 'verify_and_decrypt']:
        return "Invalid parameters"
    
    # Get the user's public key and private key
    user_keys_dir = os.path.join(KEYS_BASE_DIR + "./users", username)
    private_key_path = os.path.join(user_keys_dir, 'private_key.pem')
    symmetric_key_path = os.path.join(user_keys_dir, 'symmetric_key.pem')

    sender_keys_dir = os.path.join(KEYS_BASE_DIR + "./users", sender_username)
    sender_public_key_path = os.path.join(sender_keys_dir, 'public_key.pem')

    # Get the user's public key and private key
    if not os.path.exists(private_key_path):
        return f"Key pair not generated for {username}. Please generate keys first."
    if not os.path.exists(sender_public_key_path):
        return f"Key pair not generated for {sender_username}. Please generate keys first."

    user_private_key = load_private_key(private_key_path)
    sender_public_key = load_public_key(sender_public_key_path)

    # Decrypt and verify the file based on its name
    if file.filename.startswith('symmetric_encrypted_'):
        # Load the symmetric key
        symmetric_key = loadSymmetricKey(symmetric_key_path)

        # Decrypt the file symmetrically
        decrypt_file_symmetric(os.path.join(user_keys_dir + "/received", file.filename), os.path.join(os.path.join(user_keys_dir, 'downloaded'), 'decrypted_' + file.filename), symmetric_key)
        
        #f"Download decrypted_{file.filename[10:]}"
        return render_template('index.html')

    elif file.filename.startswith('asymmetric_encrypted_'):
        # Decrypt and verify the file asymmetrically
        decrypted_file = derive_key_and_decrypt(os.path.join(user_keys_dir + "/received", file.filename), os.path.join(os.path.join(user_keys_dir, 'downloaded'), 'decrypted_' + file.filename), sender_public_key, user_private_key)

        if verify_signature(original_file, decrypted_file, sender_public_key):
            return f"Download verified_{file.filename} (Signature verified)"
        else:
            return f"Download verified_{file.filename} (Signature verification failed)"

    return "Invalid filename"

if __name__ == '__main__':
    app.run(debug=True)