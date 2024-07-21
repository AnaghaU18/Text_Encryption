from aes_crypt import aes_encrypt, aes_decrypt
from des_crypt import des_encrypt, des_decrypt
from rsa_crypt import rsa_generate_keys, rsa_encrypt, rsa_decrypt

def main():
    print("\nWelcome to the Text Encryption Tool!")
    while True:
        print("\nOptions:\n1. AES\n2. DES\n3. RSA\n4. Exit")
        opt = int(input("Choose an option [1-4]: "))
        
        if opt in [1,2,3]:
            plaintext = input("Enter plaintext: ")
            if opt == 1:
                # AES Encryption
                aes_key = "my_aes_key"
                aes_encrypted = aes_encrypt(aes_key, plaintext)
                aes_decrypted = aes_decrypt(aes_key, aes_encrypted)
                print("\nAES Encrypted text:", aes_encrypted)
                choice = input("Would you like to decrypt the message? [y/n]: ").lower()
                if choice == 'y':
                    print("AES Decrypted text:", aes_decrypted)
                elif choice == 'n':
                    continue
                else:
                    print("Invalid entry. Please enter 'y' or 'n' only.")

            elif opt == 2:
                # DES Encryption
                des_key = "my_des_key"
                des_encrypted = des_encrypt(des_key, plaintext)
                des_decrypted = des_decrypt(des_key, des_encrypted)
                print("\nDES Encrypted text:", des_encrypted)
                choice = input("Would you like to decrypt the message? [y/n]: ").lower()
                if choice == 'y':
                    print("DES Decrypted text:", des_decrypted)
                elif choice == 'n':
                    continue
                else:
                    print("Invalid entry. Please enter 'y' or 'n' only.")

            elif opt == 3:
                # RSA Encryption
                private_key, public_key = rsa_generate_keys()
                rsa_encrypted = rsa_encrypt(public_key, plaintext)
                rsa_decrypted = rsa_decrypt(private_key, rsa_encrypted)
                print("\nRSA Encrypted text:", rsa_encrypted)
                choice = input("Would you like to decrypt the message? [y/n]: ").lower()
                if choice == 'y':
                    print("RSA Decrypted text:", rsa_decrypted)
                elif choice == 'n':
                    continue
                else:
                    print("Invalid entry. Please enter 'y' or 'n' only.")
        
        elif opt == 4:
            print("Thank you for using this tool!")
            break
        
        else:
            print("Invalid option")

    '''print("Original text:", plaintext)
    
    
    
    
    
    '''

if __name__ == "__main__":
    main()
