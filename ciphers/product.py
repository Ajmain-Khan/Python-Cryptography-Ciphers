from string import ascii_letters as letters, ascii_uppercase as ascii_upper, ascii_lowercase as ascii_lower
from ciphers.cipher_base import *

class Product(Cipher):
    '''
    A Product Cipher combines two or more transformations to create a stronger cipher. In this implementation two transformation algorithms are used.
    Specifically the ROT13 Cipher (substitution) and Railfence Cipher (transpostion).
    '''
    def __init__(self):
        super().__init__()
        self._rot13 = None  #Data space to hold each transformation applied
        self._key2 = []  #Railfence key (2 keys since 2 ciphers)
        lower = ascii_lower[13:] + ascii_lower[:13]  #Key is created by splicing part of the alphabet & adding it to the end
        upper = ascii_upper[13:] + ascii_upper[:13]
        self._key = lower + upper  #ROT13 key

    def create_railfence_matrix(self, msg, key_rails):
        '''
        The key for railfence is simply the number of 'rails' used to encrypt
            Ex:     d . . . . . t . . . . . t . . . . . f . . . . . s . . .     #Key=4 (# of rails)
                    . e . . . d . h . . . s . w . . . o . t . . . a . t . .
                    . . f . n . . . e . a . . . a . l . . . h . c . . . l .
                    . . . e . . . . . e . . . . . l . . . . . e . . . . . e
            param msg: range of message; represents the # columns.
            param key_rails: number of rails (rows).
        The plaintext is read diagonally, the ciphertext is read horizontally along the rows.
        '''
        #Create the matrix to encipher
        rails = list(range(key_rails - 1)) + list(range(key_rails - 1, 0, -1))  #Reverse direction of diagonal flow if top or bottom of rail is reached
        fences = [[None] * len(msg) for n in range(key_rails)]  #Create empty fence matrix values
        for n, x in enumerate(msg):  #Enumerate through plaintext
            fences[rails[n % len(rails)]][n] = x  #Fill fence matrix with plaintext character based on rail number
        return [c for rail in fences for c in rail if c is not None]  #Distinguish filled values from empty and return enciphered matrix

    def encrypt(self, msg, key, punc=True):
        '''
        Encrypt plaintext messages into ciphertext
            param msg(str): plaintext string.
            param key(int): Key value denoting number of columns (rails).
            param punc(bool): If True, punctuation & spaces are retained. If false, all are removed. Default: True.
            returns: The enciphered string (cipher).
        '''
        if not punc: msg = self.remove_punctuation(self.remove_whitespace(msg))
        self._rot13 = msg.translate(str.maketrans(letters, self._key))  #First encrypt using ROT13 cipher
        assert key > 0, 'Invalid Key: key='+str(key)+'. key must be greater than 0'
        self._key2 = key
        self._cipherText = ''.join(self.create_railfence_matrix(self._rot13, key)) #Next enrypt using Railfence cipher & unpack enciphered list items
        return self._cipherText

    def decrypt(self, msg, key=False, punc=True):
        '''
        Method to decrypt ciphertext messages
            param msg(str): ciphertext string.
            param key(int): Key value denoting number of columns (rails). Default: False
            param punc(bool): If True, punctuation & spaces are retained. If false, all are removed. Default: True.
            returns: The deciphered string.
        '''
        if not punc: msg = self.remove_punctuation(self.remove_whitespace(msg))
        if key:
            enciphered = self.create_railfence_matrix(range(len(msg)), key)  #Decrypt railfence first
            temp = ''.join(msg[enciphered.index(i)] for i in range(len(msg)))
            self._decryptText = temp.translate(str.maketrans(self._key, letters))  #Decrypt ROT13 second
        else:  #If no key is provided use key attribute. (assumes encrypt has been already called)
            enciphered = self.create_railfence_matrix(range(len(msg)), self._key2)
            temp = ''.join(msg[enciphered.index(i)] for i in range(len(msg)))
            self._decryptText = temp.translate(str.maketrans(self._key, letters))
        return self._decryptText

    @property
    def getkey(self):
        return self._key, self._key2

    def __str__(self):
        return 'Encrypted ROT13: {}\nEncrypted Product: {}\nROT13 Key: {}\nRailfence Key: {}\nDecrypted: {}'\
            .format(self._rot13, self._cipherText, self.getkey[0], self.getkey[1], self._decryptText)  #Encrypted Product indicates the railfence cipher