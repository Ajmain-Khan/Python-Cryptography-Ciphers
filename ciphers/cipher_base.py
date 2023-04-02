from abc import abstractmethod, ABC
from string import whitespace, punctuation

class Cipher(ABC):
    '''Abstract Base Class for cryptosystem algorithms.'''
    def __init__(self):
        self._cipherText = None
        self._decryptText = None
        self._key = None

    #Abstract Methods
    @abstractmethod
    def encrypt(self):  #Abstract method for creating encrypted message (cipher)
        pass
    @abstractmethod
    def decrypt(self):  #Abstract method for decrypting a cipher
        pass
    
    #Accessor Methods
    @property
    def ciphertext(self):
        '''Returns the cipher text in string format.'''
        return self._cipherText
    @property
    def decryptedtext(self):
        '''Returns the decrypted cipher text in string format.'''
        return self._decryptText
    @property
    def getkey(self):
        '''Returns the encryption/decryption key(s) in string format.'''
        return self._key

    def remove_punctuation(self, text):
        '''
        Remove all punctuation from a string.
            param text: string value
        '''
        return text.translate(str.maketrans('', '', punctuation))

    def remove_whitespace(self, text):
        '''
        Remove all single whitespaces from a string.
            param text: string value
        '''
        return text.translate(str.maketrans('', '', whitespace))

    def __str__(self):  #Method to print out all details
        return 'Encrypted: {}\nKey: {}\nDecrypted: {}'.format(self._cipherText, self._key, self._decryptText)
