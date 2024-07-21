'''from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

def pad_plaintext(plaintext, block_size=16):
  """Pads the plaintext to a multiple of the block size using PKCS#7.

  Args:
      plaintext: The plaintext to be padded (bytes).
      block_size: The block size of the cipher (default: 16 bytes for AES).

  Returns:
      The padded plaintext (bytes).
  """
  padding_size = block_size - (len(plaintext) % block_size)
  return plaintext + padding_size.to_bytes(block_size, byteorder='big')

def unpad_ciphertext(ciphertext, block_size=16):
  """Unpads the ciphertext using PKCS#7.

  Args:
      ciphertext: The ciphertext to be unpadded (bytes).
      block_size: The block size of the cipher (default: 16 bytes for AES).

  Returns:
      The unpadded plaintext (bytes).

  Raises:
      ValueError: If the padding is invalid.
  """
  padding_size = ciphertext[-1]
  if not 1 <= padding_size <= block_size:
    raise ValueError("Invalid padding size")
  return ciphertext[:-padding_size]

def AES_Encrypt(plaintext, password, salt_length=16, key_length=32, mode=AES.MODE_CBC):
  """Encrypts the plaintext using AES with secure key derivation.

  Args:
      plaintext: The plaintext to be encrypted (bytes).
      password: The password used for key derivation (string).
      salt_length: The length of the random salt for key derivation (default: 16 bytes).
      key_length: The desired key length (default: 32 bytes for AES-256).
      mode: The AES cipher mode (default: CBC).

  Returns:
      A tuple containing the initialization vector (IV) and the ciphertext (bytes).
  """
  salt = get_random_bytes(salt_length)
  key = PBKDF2(password.encode(), salt, key_length, count=2048)
  iv = get_random_bytes(AES.block_size)
  cipher = AES.new(key, mode, iv)
  ciphertext = cipher.encrypt(pad_plaintext(plaintext))
  return iv + ciphertext

def aes_decrypt(ciphertext, password, salt_length=16, key_length=32, mode=AES.MODE_CBC):
  """Decrypts the ciphertext using AES with secure key derivation.

  Args:
      ciphertext: The ciphertext to be decrypted (bytes).
      password: The password used for key derivation (string).
      salt_length: The length of the random salt for key derivation (default: 16 bytes).
      key_length: The desired key length (default: 32 bytes for AES-256).
      mode: The AES cipher mode used for encryption (default: CBC).

  Returns:
      The decrypted plaintext (bytes).

  Raises:
      ValueError: If the padding is invalid.
  """
  salt = get_random_bytes(salt_length)
  key = PBKDF2(password.encode(), salt, key_length, count=2048)
  iv = ciphertext[:AES.block_size]
  cipher = AES.new(key, mode, iv)
  plaintext = unpad_ciphertext(cipher.decrypt(ciphertext[AES.block_size:]))
  return plaintext

# Example usage
plaintext = b"This is a secret message"
password = "your_strong_password"

try:
  iv, ciphertext = AES_Encrypt(plaintext, password)
  decrypted_plaintext = aes_decrypt(iv + ciphertext, password)
  print("Decrypted message:", decrypted_plaintext.decode())
except ValueError as e:
  print("Error:", e)'''

'''try:
  from Crypto.Cipher import AES
  from Crypto.Random import get_random_bytes
  from Crypto.Protocol.KDF import PBKDF2
except ModuleNotFoundError:
  print("Error: The 'pycryptodome' library is not installed. Please install it using 'pip install pycryptodome'.")
  exit(1)

def pad_plaintext(plaintext, block_size=16):
  """Pads the plaintext to a multiple of the block size using PKCS#7.

  Args:
      plaintext: The plaintext to be padded (bytes).
      block_size: The block size of the cipher (default: 16 bytes for AES).

  Returns:
      The padded plaintext (bytes).
  """
  padding_size = block_size - (len(plaintext) % block_size)
  return plaintext + padding_size.to_bytes(block_size, byteorder='big')

def unpad_ciphertext(ciphertext, block_size=16):
  """Unpads the ciphertext using PKCS#7.

  Args:
      ciphertext: The ciphertext to be unpadded (bytes).
      block_size: The block size of the cipher (default: 16 bytes for AES).

  Returns:
      The unpadded plaintext (bytes).

  Raises:
      ValueError: If the padding is invalid.
  """
  padding_size = ciphertext[-1]
  if not 1 <= padding_size <= block_size:
    raise ValueError("Invalid padding size")
  return ciphertext[:-padding_size]

def AES_Encrypt(plaintext, password, salt_length=16, key_length=32, mode=AES.MODE_CBC):
  """Encrypts the plaintext using AES with secure key derivation.

  Args:
      plaintext: The plaintext to be encrypted (bytes).
      password: The password used for key derivation (string).
      salt_length: The length of the random salt for key derivation (default: 16 bytes).
      key_length: The desired key length (default: 32 bytes for AES-256).
      mode: The AES cipher mode (default: CBC).

  Returns:
      A tuple containing the initialization vector (IV) and the ciphertext (bytes).
  """
  salt = get_random_bytes(salt_length)
  key = PBKDF2(password.encode(), salt, key_length, count=2048)
  iv = get_random_bytes(AES.block_size)
  cipher = AES.new(key, mode, iv)
  ciphertext = cipher.encrypt(pad_plaintext(plaintext))
  return iv + ciphertext

def aes_decrypt(ciphertext, password, salt_length=16, key_length=32, mode=AES.MODE_CBC):
  """Decrypts the ciphertext using AES with secure key derivation.

  Args:
      ciphertext: The ciphertext to be decrypted (bytes).
      password: The password used for key derivation (string).
      salt_length: The length of the random salt for key derivation (default: 16 bytes).
      key_length: The desired key length (default: 32 bytes for AES-256).
      mode: The AES cipher mode used for encryption (default: CBC).

  Returns:
      The decrypted plaintext (bytes).

  Raises:
      ValueError: If the padding is invalid.
  """
  salt = get_random_bytes(salt_length)
  key = PBKDF2(password.encode(), salt, key_length, count=2048)
  iv = ciphertext[:AES.block_size]
  cipher = AES.new(key, mode, iv)
  plaintext = unpad_ciphertext(cipher.decrypt(ciphertext[AES.block_size:]))
  return plaintext

# Example usage
plaintext = b"This is a secret message"
password = "your_strong_password"

try:
  iv, ciphertext = AES_Encrypt(plaintext, password)
  decrypted_plaintext = aes_decrypt(iv + ciphertext, password)
  print("Decrypted message:", decrypted_plaintext.decode())  # Decode bytes to string
except ValueError as e:
  print("Error:", e)
'''

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def AES_Encrypt(plaintext, key):
  """Encrypts the plaintext using AES encryption with secure practices.

  Args:
      plaintext: The plaintext to be encrypted (string).
      key: The secret key for encryption (string).

  Returns:
      The encrypted ciphertext (bytes).

  Raises:
      ValueError: If the key length is not a multiple of 16 bytes.
  """

  # Validate key length (must be multiple of 16 bytes)
  if len(key) % 16 != 0:
    raise ValueError("Key length must be a multiple of 16 bytes")

  # Convert plaintext and key to bytes
  plaintext_bytes = plaintext.encode('utf-8')
  key_bytes = key.encode('utf-8')

  # Pad the plaintext to a multiple of the block size using PKCS#7
  plaintext_padded = pad(plaintext_bytes, AES.block_size)

  # Create AES cipher object with CBC mode
  cipher = AES.new(key_bytes, AES.MODE_CBC)

  # Encrypt the padded plaintext
  ciphertext = cipher.encrypt(plaintext_padded)

  print(ciphertext)

plaintext = "This is a secret message to be encrypted."
key = "ThisIsA!Strong&Secure_Key123_More_Random_Characters"

try:
  ciphertext = AES_Encrypt(plaintext, key)
  print("Encrypted ciphertext:", ciphertext.hex())  # Print in hex format for readability

  # Decryption (not shown here for brevity) would involve using aes_decrypt()
except ValueError as e:
  print("Error:", e)
