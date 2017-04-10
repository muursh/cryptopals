#cryptopals challenge 18

import struct
from Crypto.Cipher import AES


def run_ctr(data, key):
    return xor(data, AES_CTR_keystream(key))


def xor(x, y):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(x, y))


def AES_ECB_encrypt(string, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(string)


def AES_CTR_keystream(key):
    block = 0
    while True:
        keystream_block = AES_CTR_keystream_block(key, block)
        for i in keystream_block:
            yield i
        block = block + 1


def AES_CTR_keystream_block(key, block_number):
    alpha = struct.pack('<Q', 0)
    beta = struct.pack('<Q', block_number)
    return AES_ECB_encrypt(alpha + beta, key)


input = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='.decode('base64')
print (run_ctr(input, 'YELLOW SUBMARINE'))

