#cryptopals challenge 27
from os import urandom
from Crypto.Cipher import AES

iv = urandom(16)
s1 = b"comment1=cooking%20MCs;userdata="
s2 = b";comment2=%20like%20a%20pound%20of%20bacon"

xor = lambda b1, b2: bytes(x ^ y for x, y in zip(b1, b2))

def encrypt(plain):
    #create cipher
    cipher = AES.new(iv, AES.MODE_CBC, iv)
    #delete chars - same as c26
    string = plain.translate(str.maketrans({';': '', '=': ''}))
    string = pkcs7(string.encode('ascii'))
    return cipher.encrypt(string)


def decrypt(encrypted):
    cipher = AES.new(iv, AES.MODE_CBC, iv)
    message = cipher.decrypt(encrypted)
    return message[:-message[-1]]


#crypto message syntax
def pkcs7(string):
    pad = 16 - (len(string) % 16)
    return string + bytes(pad * [pad])


def crack_cipher(cipher):
    decrypted = decrypt(cipher)
    #all chars between 32 and 127
    return "a" if all(32<ch<127 for ch in decrypted) else decrypted


plain = "abcdefghijklmnopqrstuvwxyz"
cipher = encrypt(plain)
tmp = cipher[0:16] + bytes(16) + cipher[0:16] + cipher[16:]
cracked = crack_cipher(tmp)

if (iv == xor(cracked[0:16], cracked[32:48])):
    print('True')
    print(iv)
    print(xor(cracked[0:16], cracked[32:48]))
else:
    print('False')
