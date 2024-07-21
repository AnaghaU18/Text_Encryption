from Crypto.Cipher import AES
import base64

def aes_encrypt(key, plaintext):
    key = key.zfill(32).encode()  # Ensure key length is 32 bytes for AES-256
    iv = b'1234567890123456'  # 16 bytes IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = _pad(plaintext).encode()
    encrypted_text = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_text).decode()

def aes_decrypt(key, encrypted_text):
    key = key.zfill(32).encode()
    iv = b'1234567890123456'  # 16 bytes IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decoded_encrypted_text = base64.b64decode(encrypted_text)
    decrypted_text = cipher.decrypt(decoded_encrypted_text)
    return _unpad(decrypted_text.decode())

def _pad(text):
    # Padding to ensure text length is a multiple of 16 bytes
    pad_len = 16 - len(text) % 16
    return text + pad_len * chr(pad_len)

def _unpad(text):
    # Remove padding
    pad_len = ord(text[-1])
    return text[:-pad_len]
