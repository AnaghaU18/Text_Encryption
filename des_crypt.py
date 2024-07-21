from Crypto.Cipher import DES
import base64

def des_encrypt(key, plaintext):
    key = key[:8].zfill(8).encode()  # Ensure key length is exactly 8 bytes for DES
    iv = b'12345678'  # 8 bytes IV
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_text = _pad(plaintext).encode()
    encrypted_text = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_text).decode()

def des_decrypt(key, encrypted_text):
    key = key[:8].zfill(8).encode()  # Ensure key length is exactly 8 bytes for DES
    iv = b'12345678'  # 8 bytes IV
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decoded_encrypted_text = base64.b64decode(encrypted_text)
    decrypted_text = cipher.decrypt(decoded_encrypted_text)
    return _unpad(decrypted_text.decode())

def _pad(text):
    # Padding to ensure text length is a multiple of 8 bytes
    pad_len = 8 - len(text) % 8
    return text + pad_len * chr(pad_len)

def _unpad(text):
    # Remove padding
    pad_len = ord(text[-1])
    return text[:-pad_len]
