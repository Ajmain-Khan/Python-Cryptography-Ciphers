import re
from random import shuffle
from string import ascii_uppercase as ascii_upper
from ciphers.cipher_base import *

class Playfair(Cipher):
    '''
    The Playfair cipher is a digraph (two letter) substitution cipher. It uses key that is a 5x5 keysquare where one letter (usually j) is omitted.
    Consecutive repeating letters (hello) are replaced with an x (helxo).
    If the plaintext has an odd number of characters, an x is added at the end to make it even.
    The plaintext is split into pairs and enciphered according to the Playfair Cipher. The letter J is replaced by the letter I.
        Sample keysquare:
        A D R L Y
        O B H M P
        S G U X N
        F K E Q Z
        C V W I T
        
        param key: Keysquare, as a 25 unique character string.
    '''
    def __init__(self, key=None):
        super().__init__()
        self._key = key

    def key_create(self):
        '''
        Randomly generate keysquare to use as the key to encrypt plaintext.
            returns: key (string) containing 25 letters of the alphabet'''
        keysquare = list(ascii_upper.replace('J', '')) #Replace letter J with I as per convention
        shuffle(keysquare)
        self._key = ''.join(keysquare)
        return self._key

    def encode_pair(self, a, b):
        '''Encode pairs of characters based on keysquare'''
        if b == a:
            b = 'X'  #Replace indentical subsequent letters with 'X"
        #
        row_a, col_a = int(self._key.index(a)/5), self._key.index(a)%5  #Format index of characters into row/columns grid (5x5 keysquare)
        row_b, col_b = int(self._key.index(b)/5), self._key.index(b)%5
        #Paring Shifts (Shifts are wrapped around if they exceed one side of the keysquare grid)
        if row_a == row_b:
            #If pairs in same row, the characters a & b take the value of the characters directly to the right (one column right)
            return self._key[row_a*5 + (col_a + 1)%5] + self._key[row_b*5 + (col_b + 1)%5]  #Map pairs in same row
        elif col_a == col_b:
            #If pairs in same column, the characters a & b take the value of the characters directly below (one row below)
            return self._key[((row_a + 1)%5)*5 + col_a] + self._key[((row_b + 1)%5)*5 + col_b] #Map pairs in same column
            #If pairs form two corners of a 'box', characters a & b take the value of the opposite corners of the 'box'.
        else: return self._key[row_a*5 + col_b] + self._key[row_b*5 + col_a]  #Map pairs forming corners of a box (cross-connections)

    def decode_pair(self, a, b):
        '''Decode pairs of characters based on keysquare'''
        assert a != b, 'Illegal Pairing: Identical consecutive characters.'
        row_a, col_a = int(self._key.index(a)/5), self._key.index(a)%5
        row_b, col_b = int(self._key.index(b)/5), self._key.index(b)%5
        if row_a == row_b: return self._key[row_a*5 + (col_a - 1)%5] + self._key[row_b*5 + (col_b - 1)%5]  #Opposite to encoding: characters shift left
        elif col_a == col_b: return self._key[((row_a - 1)%5)*5 + col_a] + self._key[((row_b - 1)%5)*5 + col_b]  #Characters shift up
        else: return self._key[row_a*5 + col_b] + self._key[row_b*5 + col_a]  #Characters still take the value of the opposite corner

    def encrypt(self, msg):
        '''
        Encrypt plaintext messages into ciphertext
            param msg(str): plaintext string.
            returns: The enciphered string (cipher).
        '''
        msg = self.remove_punctuation(self.remove_whitespace(msg)).upper()  #Since only text is supported, remove all whitespace & punctuation
        msg = re.sub('J', 'I', msg)  #Replace all occurances of the letter J with I
        if self._key == None: self.key_create()
        if len(msg) % 2 != 0:  #If plaintext has an odd number of chars, append 'X' to the plaintext
            msg += 'X'
        result = ''
        for c in range(0, len(msg), 2):  #Loop through every 2nd letter
            result += self.encode_pair(msg[c], msg[c + 1])  #Pass in pairs of characters (0 & 1), (2, 3), etc. to encipher
        self._cipherText = result
        return self._cipherText   

    def decrypt(self, msg):
        '''
        Method to decrypt ciphertext messages
            param msg(str): ciphertext string.
            returns: The deciphered string.
        '''
        msg = self.remove_punctuation(self.remove_whitespace(msg))
        if len(msg) % 2 != 0:
            msg += 'X'
        result = ''
        for c in range(0, len(msg), 2):
            result += self.decode_pair(msg[c], msg[c + 1])
        self._decryptText = result
        return self._decryptText