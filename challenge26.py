#cryptopals challenge 26

from os import urandom
from Crypto.Cipher import AES

rand_key = urandom(16)
IV = urandom(8)
s1 = b"comment1=cooking%20MCs;userdata="
s2 = b";comment2=%20like%20a%20pound%20of%20bacon"

xor = lambda b1, b2: bytes(x ^ y for x, y in zip(b1, b2))

def encrypt(plain):
    #clean string
    string = plain.translate(str.maketrans({';': '', '=': ''}))
    string = s1 + string.encode('ascii') + s2
    return ctrenc(rand_key, 0, string)


def decrypt(user_input):
    plain = ctrenc(rand_key, 0, user_input)
    return plain


#symmetric encryption
def ctrenc(key, counter, plain):
    cipher = AES.new(key, AES.MODE_ECB)
    n = IV + counter.to_bytes(8, 'little')
    blk = xor(plain, cipher.encrypt(n))
    min_len = min(len(plain), 16)
    if min_len:
        return blk + ctrenc(key, counter+1, plain[min_len:])
    else:
        return blk


def isadmin(cipher_string):
    return b";admin=true;" in decrypt(cipher_string)

#test string
user_input = bytearray(encrypt('.admin.true'))

#bit flipping
user_input[32] ^= ord('.') ^ ord(';') 
user_input[38] ^= ord('.') ^ ord('=')

print(isadmin(bytes(user_input)))
