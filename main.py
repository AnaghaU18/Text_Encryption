import AES

def main():
    print("Welcome to the Text Encryption Program.")
    while True:
        opt = int(input('''Options:
        1. AES
        2. DES
        3. RSA
        4. Cancel
    Select an option (1-4): '''))
        
        if opt in (1,2,3):
            plaintext = input("Enter plaintext: ")
            key = input("Enter secret key: ")
            if opt == 1:
                AES.AES_Encrypt(plaintext, key)
            elif opt == 2:
                DES.DES_Encrypt(plaintext, key)
            else:
                RSA.RSA_Encrypt(plaintext, key)
        elif opt == 4:
            print("Thank you for using Text Encryption Project!")
            break
        else:
            print("Invalid input. Please enter the correct input.")


if __name__ == "__main__":
    main()