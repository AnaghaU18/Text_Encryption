# rsa_crypt.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def rsa_generate_keys():
    # Generate a new RSA key pair (private and public key)
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return private_key, public_key

def rsa_encrypt(public_key, plaintext):
    # Import the public key
    public_key = RSA.import_key(public_key.encode())
    # Create a new cipher object using the public key
    cipher = PKCS1_OAEP.new(public_key)
    # Encrypt the plaintext
    encrypted_text = cipher.encrypt(plaintext.encode())
    # Encode the encrypted text in base64 to make it easier to handle
    return base64.b64encode(encrypted_text).decode()

def rsa_decrypt(private_key, encrypted_text):
    # Import the private key
    private_key = RSA.import_key(private_key.encode())
    # Create a new cipher object using the private key
    cipher = PKCS1_OAEP.new(private_key)
    # Decode the encrypted text from base64
    decoded_encrypted_text = base64.b64decode(encrypted_text)
    # Decrypt the text
    decrypted_text = cipher.decrypt(decoded_encrypted_text)
    return decrypted_text.decode()
