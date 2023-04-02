from random import choice
from ciphers.substitution import Substitution
from ciphers.playfair import Playfair
from ciphers.caesar import Caesar
from ciphers.transposition import ColumnarTransposition
from ciphers.product import Product
from ciphers.RSA import RSA

def main():
    while True: #Repeats until user stops
        try:
            userIn = input("Enter message to encrypt:\n")

            #Instantiate Classes
            cipher_Sub = Substitution()
            cipher_Play = Playfair()
            cipher_Caesar = Caesar()
            cipher_ColTrans = ColumnarTransposition()
            cipher_Product = Product()
            cipher_RSA = RSA()

            randNum = choice(range(1, 7))  #Used to randomly select a cipher
            #Randomly call a cipher
            if randNum == 1:
                try:
                    cipher_Sub.encrypt(userIn)
                    cipher_Sub.decrypt(cipher_Sub.ciphertext)
                    print('\n| SUBSTITUTION CIPHER |\n{}'.format(cipher_Sub))
                except Exception as e:
                    print(e)
            if randNum == 2:
                try:
                    cipher_Play.encrypt(userIn)
                    cipher_Play.decrypt(cipher_Play.ciphertext)
                    print('\n| PLAYFAIR CIPHER |\n{}'.format(cipher_Play))
                except Exception as e:
                    print(e)
            if randNum == 3:
                try:
                    cipher_Caesar.encrypt(userIn)
                    cipher_Caesar.decrypt(cipher_Caesar.ciphertext)
                    print('\n| CAESAR CIPHER |\n{}'.format(cipher_Caesar))
                except Exception as e:
                    print(e)
            if randNum == 4:
                try:
                    cipher_ColTrans.encrypt(userIn)
                    cipher_ColTrans.decrypt(cipher_ColTrans.ciphertext)
                    print('| COLUMNAR TRANSPOSITION CIPHER |\n{}'.format(cipher_ColTrans))
                except Exception as e:
                    print(e)
            if randNum == 5:
                try:
                    cipher_Product.encrypt(userIn, 5)
                    cipher_Product.decrypt(cipher_Product.ciphertext)
                    print('\n| PRODUCT CIPHER |\n{}'.format(cipher_Product))
                except Exception as e:
                    print(e)
            if randNum == 6:
                try:
                    cipher_RSA.encrypt(userIn, 7, 11)
                    cipher_RSA.decrypt(cipher_RSA.ciphertext)
                    print('\n| RSA CIPHER |\n{}'.format(cipher_RSA))
                except Exception as e:
                    print(e)
            in_exit = input("\nContinue? (y/n)\n").lower()
            if in_exit == 'n' or in_exit == 'no':
                break
        except Exception as e:
            print("An Exception Occurred: ", e)

if __name__ == "__main__":
    main()