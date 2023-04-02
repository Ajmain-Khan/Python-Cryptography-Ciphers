from random import randint
from string import ascii_letters as letters, ascii_uppercase as ascii_upper, ascii_lowercase as ascii_lower
from ciphers.cipher_base import *

class Caesar(Cipher):
    '''
    The Caesar Cipher has a key consists of an integer 1-25. This key integer x is used to offset the alphabet by x.
    Letters are encrypted according to the following equation::

        Let c be the ciphertext, and p be the plaintext
            c = (p + key)%26
   '''
    def __init__(self):
        super().__init__()
        self._shift = ''
    
    def key_create(self):
        '''Creates a key (shifted alphabet) offset by a random value. To support both upper & lower case, both alphabets cases are shifted.'''
        self._shift = randint(1, 25)  #Random shift value between 1-25
        lower = ascii_lower[self._shift:] + ascii_lower[:self._shift]  #Key is created by splicing part of the alphabet & adding it to the end
        upper = ascii_upper[self._shift:] + ascii_upper[:self._shift]
        self._key = lower + upper  #Upper & lowercases combined to support different cases
        return self._key

    def encrypt(self, msg, shift=False, punc=True):
        '''
        Encrypt plaintext messages into ciphertext
            param msg(str): plaintext string.
            param shift(int): Offset key. Allowable values are integers 0-25. Default: False
            returns: The enciphered string (cipher).
        '''
        if not punc: msg = self.remove_punctuation(msg)
        if shift:
            assert shift >= 0 and shift <= 26, 'Offset key must be between 0-25'
            self._shift = shift
            result = ''
            for c in msg:
                if c.isalpha():
                    if c.isupper(): result += chr((ord(c) + shift-65) % 26 + 65)  #For uppercase letters
                    else: result += chr((ord(c) + shift-97) % 26 + 97)  #For lowercase letters
                else: result += c
            self._cipherText = result
        else:  #If no shift value is provided, this section creates a random shifted alphabet to use as a key
            table_encipher = str.maketrans(letters, self.key_create())  #Translation table for converting normal alphabet characters to its offsetted equivalent
            self._cipherText = msg.translate(table_encipher)
        return self._cipherText
    
    def decrypt(self, msg, shift=False, punc=True):
        '''
        Method to decrypt ciphertext messages
            param msg(str): ciphertext string.
            param shift(int): Offset key. Allowable values are integers 0-25. Default: False
            param punc(bool): If True, punctuation & spaces are retained. If false, all are removed. Default: True.
            returns: The deciphered string.
        '''
        if not punc: msg = self.remove_punctuation(msg)
        if shift:  #If shift is passed, use as the key. This allows to decrypt already encrypted messages without first encrypting one
            result = ''
            for c in msg:
                if c.isalpha():
                    if c.isupper(): result += chr((ord(c) - shift-65) % 26 + 65)  #For uppercase letters
                    else: result += chr((ord(c) - shift-97) % 26 + 97)  #For lowercase letters
                else: result += c
            self._decryptText = result
        else:
            table_decipher = str.maketrans(self._key, letters)  #If no key is passed, a random one is created using key_create method
            self._decryptText = msg.translate(table_decipher)
        return self._decryptText

    def checkKeys(self):
        if self._key == None: return 'Shift: {}'.format(self._shift)
        else: return 'Key: {}\nShift: {}'.format(self._key, self._shift)

    def __str__(self):
        return 'Encrypted: {}\n{}\nDecrypted: {}'.format(self._cipherText, self.checkKeys(), self._decryptText)
