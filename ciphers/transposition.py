from ciphers.cipher_base import *

class ColumnarTransposition(Cipher):
    """
    The Columnar Transposition Cipher is a fractionating cipher. It has a key consisting of a word with all unique letters.
    The plaintext is written out in rows, and the ciphertext is read column by column.
        param key(str): Keyword. Must consist of unique alphabetical characters only, no punctuation or numbers.    
    """
    def __init__(self, keyword = 'ALGORITHMS'):
        super().__init__()
        self._key = keyword.upper()
        assert len(keyword) > 0, 'Invalid Keyword in __init__: Keyword length must be >= 1'

    def key_create(self, key):
        self._key = key.upper()
        assert len(key) > 0, 'Invalid Keyword in key_create: Keyword length must be >= 1'

    def indices_sorted(self, keyword):
        '''
        Sorted indices of a word for encryption
            Ex. ALGORITHMS = [0,4,1,6,7,3,9,2,5,8]
        '''
        ind1 = [(keyword[i], i) for i in range(len(keyword))]  #indicies are assigned based on priority in the alphabet
        ind2 = [(k[1], i) for i, k in enumerate(sorted(ind1))]
        return [sortInd[1] for sortInd in sorted(ind2)]
            
    def indices_resort(self, keyword):
        '''Unsorted indices for decrypting'''
        ind1 = [(keyword[i], i) for i in range(len(keyword))]  #Reverses what is done in sort method
        return [unsortInd[1] for unsortInd in sorted(ind1)]  

    def encrypt(self, msg, key=False):
        '''
        Encrypt plaintext messages into ciphertext
            param msg(str): plaintext string.
            param key(str): permutation of the 26 characters of the alphabet. Default: False
            returns: The enciphered string (cipher).
        '''
        if key:
            self.key_create(key)
        msg = self.remove_punctuation(self.remove_whitespace(msg))    
        result = ''
        indices = self.indices_sorted(self._key)
        for i in range(len(self._key)):
            result += msg[indices.index(i)::len(self._key)]
        self._cipherText = result
        return self._cipherText

    def decrypt(self, msg):
        '''
        Method to decrypt ciphertext messages
            param msg(str): ciphertext string.
            returns: The deciphered string.
        '''
        msg = self.remove_punctuation(self.remove_whitespace(msg))
        result = ['_']*len(msg)
        lenMsg, lenKey = len(msg), len(self._key) #Calculate row & column of the matrix
        indexes = self.indices_resort(self._key)
        ceil = 0
        for i in range(len(self._key)):
            thiscollen = (int)(lenMsg/lenKey)  #Max row of the matrix
            if indexes[i] < lenMsg % lenKey:
                thiscollen += 1
            result[indexes[i]::lenKey] = msg[ceil:ceil+thiscollen]
            ceil += thiscollen
        self._decryptText = ''.join(result)
        return self._decryptText