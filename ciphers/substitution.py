from random import shuffle
from string import ascii_uppercase as ascii_upper, ascii_lowercase as ascii_lower
from ciphers.cipher_base import *

class Substitution(Cipher):
    '''
    The Substitution Cipher uses a key that consists of a scrambled alphabet; A.K.A mixed alphabet or deranged alphabet.
    e.g. 'uvwxyzabcdefghijklmnopqrst' *The key may also contain numbers or punctuation*
    Letter are encrypted according to the following algorithm:

        plaintext =  abcdefghijklmnopqrstuvwxyz
        ciphertext = uvwxyzabcdefghijklmnopqrst

    To encipher, take the desired plaintext letter and substitute it with the ciphertext below it.
    '''
    def __init__(self):
        super().__init__()
    
    #Create Secret Key Method
    def key_create(self):
        '''
        Create a random permutation of the alphabet to use as the key.
            returns: String containg a scrambled alphabet key
        '''
        self.randKey = list(ascii_lower)  #Create a list of alphabet letters
        shuffle(self.randKey)  #Shuffle all the characters
        self._key = ''.join(self.randKey)  #Return the randomized list of characters as a string
        return self._key
    
    #Encryption Method
    def encrypt(self, msg, key=False, punc=True):
        '''
        Encrypt plaintext messages into ciphertext
            param msg(str): plaintext string.
            param key(str): permutation of the 26 characters of the alphabet.
            param punc(bool): If True, punctuation & spaces are retained. If false, all are removed. Default: True.
            returns: The enciphered string (cipher).
        '''
        if not punc:  #If punc is false
            msg = self.remove_punctuation(self.remove_whitespace(msg))  #Remove punctuation and whitespaces from plaintext
        if key:  #Check if a key argument is passed in by user
            assert len(set(key)) >= 26, 'Key must contain atleast all alphabet letters with no repeating characters.'
            self._key = key.upper()
            #zip() method is used to create a dictionary of plaintext keys associated with cyphertext values, vice versa for decryption
            keyMap = dict(zip(ascii_lower, self._key))  #Create a dictionary of plaintext & ciphertext characters as key, value pairs
        else:  #If no key is passed in, call the key_create function
            keyMap = dict(zip(ascii_lower, self.key_create()))  #We're able to call key_create() in one line since it has a return value
        #Parse each char in msg, pass the char as dict key, and add the value in dict (if it exists) to variable [self.cipherText]
        self._cipherText = ''.join(keyMap.get(char.lower(), char) for char in msg)  #If the variable doesn't exist, the char is passed in instead
        return self._cipherText
    
    #Decryption Method
    def decrypt(self, msg, key=False, punc=True):
        '''
        Method to decrypt ciphertext messages
            param msg(str): ciphertext string.
            param key(str): permutation of the 26 characters of the alphabet.
            param punc(bool): If True, punctuation & spaces are retained. If false, all are removed. Default: True.
            returns: The deciphered string.
        '''
        if not punc: msg = self.remove_punctuation(msg)
        if key: keyMap = dict(zip(key, ascii_upper))  #Similar to encrypt except ciphertext & plaintext chars as key, value pairs
        else: keyMap = dict(zip(self._key, ascii_upper))
        self._decryptText = ''.join(keyMap.get(char.lower(), char) for char in msg)
        return self._decryptText