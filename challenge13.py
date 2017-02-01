# Cryptopals challenge 13

from random import randint
from Crypto.Cipher import AES


def gen_rand_string(n):
    return ''.join(chr(randint(0, 255)) for _ in range(n))


def encrypt_ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


def decrypt_ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)


def pad(string, padsize):
    padded_size = padsize - (len(string) % padsize)
    if padded_size == 0:
        padded_size = padsize
    return string + chr(padded_size) * padded_size


def unpad(string, padsize):
    if len(string) % padsize != 0:
        return string
    must_unpad = ord(string[-1])
    if must_unpad < 0 or must_unpad > padsize:
        return string
    return string[:-must_unpad]


def parse(string):
    string = string.split('&')
    string = [x.split('=') for x in string]
    ret = {k: v for k, v in string}
    return ret


oracle_key = gen_rand_string(16)


def profile_for(email):
    email = email.replace('=', '').replace('&', '')
    profile = 'email=' + email + '&uid=10&role=user'
    return encrypt_ecb(pad(profile, 16), oracle_key)


def user_profile(enc):
    return parse(unpad(decrypt_ecb(enc, oracle_key), 16))


a = profile_for('XXXXXXXXXXXXX')
b = profile_for('XXXXXXXXXX' + pad('admin', 16))

test = a[:32] + b[16:32]
print user_profile(test)

