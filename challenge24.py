#cryptopals challenge24

from Crypto.Random.random import getrandbits
from challenge21 import MT19937

def encrypt(plaintext, seed = 0xffff):
    prng = MT19937(seed)
    encrypted_message = b''
    for char in plaintext:
        encrypted_message += bytes([char ^ prng.extract() & 255])
    return encrypted_message


def verify(message = bytes(10), s = 0xffff):
    encrypted_message = encrypt(message, s)
    plaintext = encrypt(encrypted_message, s)
    if (message == plaintext):
        return True
    return False


def decrypt(encrypted_message):
    plaintext = bytes("A" * len(encrypted_message), "ascii")
    for seed in range(0xffff):
        if encrypted_message[-10:] == encrypt(plaintext, seed)[-10:]:
            return seed


seed = getrandbits(16)
start = bytes(getrandbits(8) for i in range(10))
plaintext = start + bytes("A" * 10, "ascii")
verify()
encrypted_message = encrypt(plaintext, seed)
calculated_seed = decrypt(encrypted_message)

if (calculated_seed == seed):
    print(calculated_seed)
else:
    print('error')
