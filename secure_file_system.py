


# User Authentication
def hash_password(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def verify_password(password, key, salt):
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    try:
        derived_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return derived_key == key
    except Exception:
        return False


# Symmetric Encryption and Decryption
def generate_symmetric_key():
    return Fernet.generate_key()


def encrypt_file_symmetric(file_path, key):
    cipher_suite = Fernet(key)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = cipher_suite.encrypt(file_data)
    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)
    os.remove(file_path)


def decrypt_file_symmetric(file_path, key):
    cipher_suite = Fernet(key)
    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    original_file_path = file_path.replace('.enc', '')
    with open(original_file_path, 'wb') as file:
        file.write(decrypted_data)
    os.remove(file_path)


# Asymmetric Encryption and Decryption
def generate_asymmetric_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_key_with_rsa(symmetric_key, public_key):
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted_key


def decrypt_key_with_rsa(encrypted_key, private_key):
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted_key


# File Integrity
def generate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as file:
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def verify_file_hash(file_path, original_hash):
    current_hash = generate_file_hash(file_path)
    return current_hash == original_hash


# Main Function
def main():
    print("Welcome to the Secure File Encryption and Decryption System!")
    print("1. Register")
    print("2. Login")
    choice = input("Enter your choice (1 or 2): ")

    # Simple registration system
    if choice == '1':
        password = getpass.getpass("Set a password: ")
        key, salt = hash_password(password)
        print("Registration complete! Please remember your password.")
        return key, salt
    elif choice == '2':
        password = getpass.getpass("Enter your password: ")
        key, salt = hash_password(password)  # Replace with stored values in real applications
        if verify_password(password, key, salt):
            print("Login successful!")
        else:
            print("Login failed!")
            return

    # Key Generation
    symmetric_key = generate_symmetric_key()
    private_key, public_key = generate_asymmetric_key_pair()

    # Encrypt and Decrypt File
    file_path = input("Enter the file path to encrypt: ")
    original_hash = generate_file_hash(file_path)
    encrypt_file_symmetric(file_path, symmetric_key)
    print(f"File encrypted successfully! Original hash: {original_hash}")

    encrypted_symmetric_key = encrypt_key_with_rsa(symmetric_key, public_key)

    decrypt_file_symmetric(file_path + '.enc', symmetric_key)
    print("File decrypted successfully!")

    decrypted_hash = generate_file_hash(file_path)
    if verify_file_hash(file_path, original_hash):
        print("File integrity verified!")
    else:
        print("File integrity check failed!")


if __name__ == "__main__":
    main()
