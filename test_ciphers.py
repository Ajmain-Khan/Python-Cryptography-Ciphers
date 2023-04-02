'''
Execute this program to quickly evaluate a sample output for each of the 6 encryption algorithms.
'''
from ciphers.substitution import Substitution
from ciphers.playfair import Playfair
from ciphers.caesar import Caesar
from ciphers.transposition import ColumnarTransposition
from ciphers.product import Product
from ciphers.RSA import RSA

def test_methods():
    sampleTxt = "HELLO! We're self-quarantining; to maintain good health, stay safe... Bye!"
    print('Plain Text:', sampleTxt, '\n================================================================================================')
    
    print('#### SUBSTITUTION CIPHER ####')
    msgSub = Substitution()
    msgSub.encrypt(sampleTxt)
    msgSub.decrypt(msgSub.ciphertext)
    print(msgSub, '\n', '================================================================================================')

    print('#### PLAYFAIR CIPHER ####')
    msgPlay = Playfair()
    msgPlay.encrypt(sampleTxt)
    msgPlay.decrypt(msgPlay.ciphertext)
    print(msgPlay, '\n', '================================================================================================')

    print('#### CAESAR CIPHER ####')
    msgCaesar = Caesar()
    msgCaesar.encrypt(sampleTxt)
    msgCaesar.decrypt(msgCaesar.ciphertext)
    print(msgCaesar, '\n', '================================================================================================')

    print('#### COLUMNAR TRANSPOSITION CIPHER ####')
    msgTrans = ColumnarTransposition('PROGRAM')
    msgTrans.encrypt(sampleTxt)
    msgTrans.decrypt(msgTrans.ciphertext)
    print(msgTrans, '\n', '================================================================================================')

    print('#### PRODUCT CIPHER ####')
    msgProduct = Product()
    msgProduct.encrypt(sampleTxt, 5)
    msgProduct.decrypt(msgProduct.ciphertext, 5)
    print(msgProduct, '\n', '================================================================================================')

    print('#### RSA CIPHER ####')
    msgRSA = RSA()
    msgRSA.encrypt(sampleTxt, 7, 11)
    msgRSA.decrypt(msgRSA.ciphertext)
    print(msgRSA, '\n', '================================================================================================')

test_methods()