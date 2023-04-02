from random import choice
from ciphers.cipher_base import *

class RSA(Cipher):
    '''
    RSA is an assymetric cryptography algorithm; there are (usually) two keys; a public key & a private key.
    The public key enciphers messages and a secret private key is used for deciphering these messages. This is a greatly oversimplified
    implementation of the RSA algorithm that uses small integers and does not include features such as the Chinese Remaineder Theorem,
    and the key size only goes upto 100
    '''
    def __init__(self):
        super().__init__()
        self._p = 0
        self._q = 0
        self._key_public = 0  # key[0] = public key, key[1] = private key
        self._key_private = 0
    def gcd(self, a, b):
        '''Euclidean algorithm for determining the greatest common divisor/factor'''
        while b != 0:
            a, b = b, a % b
        return a

    def is_prime(self, n):
        '''Checks whether number is prime or not'''
        if n == 2: return True
        elif n < 2 or n % 2 == 0: return True
        elif n > 2:
            for i in range(2, n):  #Find factors
                if not n % i: return False
        return True

    def generate_prime(self):
        '''Generates a list of random prime numbers and returns a random one'''
        prime_list = [i for i in range(5, 100) if self.is_prime(i)]  #Depending on the number, this sometimes doesn't work mainly due to unicode
        return choice(prime_list)

    def encrypt(self, msg, p=None, q=None, punc=True):
        '''Encrypts plaintext using public key'''
        if not p and not q:  #If a prime number isn't passed in, it is generated
            self._p, self._q = self.generate_prime(), self.generate_prime()
        elif not self.is_prime(p) and self.is_prime(q): raise ValueError('Both numbers must be prime!')
        elif p == q: raise ValueError('P and Q cannot be equivalent!')
        else: self._p, self._q = p, q  #(Step 1 in PDF)
        msg = self.remove_punctuation(msg)
        self.generate_keys(self._p, self._q)
        e, n = self._key_public  #Unpack Public key
        result = []
        for i in msg:
            if i.isupper():
                p = ord(i)-65  #Get unicode value for uppercase alphabet
                c = (p**e) % n  #Encryption equation (Step 7 in PDF)
                result.append(c)
            elif i.islower():
                p = ord(i)-97 #Get unicode value for lowercase alphabet
                c = (p**e) % n
                result.append(c)
            elif i.isspace(): result.append(666)  #Unique value for space character
        self._cipherText = result
        return self._cipherText

    def decrypt(self, msg):
        '''Decrypts cipher text using private key'''
        d, n = self._key_private  #Unpack Private key
        result = ''
        for i in msg:
            if i==666: result+=' '  #Value is space if encrypted text is a specific value
            else:
                p = ((i**d)%n) + 97  #Decryption equation (Step 7 in PDF), add 65 or 97 to get unicode representation of upper or lower case alphabet resepectively
                p = chr(p)  #Convert back to string
                result += p
        self._decryptText = result
        return self._decryptText

    def generate_keys(self, p, q):
        n = p*q  #RSA Modulus (Step 2 in PDF)
        #Eulers Totient Function
        phi_n = (p-1)*(q-1)  #Phi is the name of the symbol to denote totient of n (Step 3 in PDF)
        #Finding e (Step 4 in PDF)
        for i in range(1, 100):  #Find possible value for e within 1000
            if self.gcd(i, phi_n) == 1:  #e must be coprime with phi, use Euclid's algorithm to prove
                e=i
        #Finding d (Step 5 in PDF)
        d = self.mult_inverse(e, phi_n)
        self._key_public = (e, n)
        self._key_private = (d, n)
    
    def euclidean_ext_gcd(self, a, b):
        '''The extended euclidean algorithm is used to find gcd of integers a, b and find integers x, y such that [ax+by=gcd(a,b)].
        It is essentially a recursive algorithm to continually repeat division of two integers until remainder is 0'''
        if a % b == 0: return b, 0, 1
        else:
            gcd, x, y = self.euclidean_ext_gcd(b, a % b)  #Recursive call
            x = x - ((a//b)*y)  #// = floating point
            return gcd, y, x
    
    def mult_inverse(self, e, phi):
        '''Find the multiplicative inverse of two numbers'''
        gcd, d, temp = self.euclidean_ext_gcd(e, phi)
        del temp
        if gcd != 1: return None
        else: return d % phi  #Step 5 in PDF

    @property
    def getkey(self):
        return self._key_public, self._key_private

    def __str__(self):
        return 'Encrypted: {}\nPublic Key: {}\nPrivate Key: {}\nDecrypted: {}'.format(self._cipherText, self.getkey[0], self.getkey[1], self._decryptText)