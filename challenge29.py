#Cryptopals challenge 29

from sha1 import sha1hash
import hashlib
import struct

def get_pad(message, key_len):
    byte_len = len(message) + key_len
    pad = b''
    pad += b'\x80'
    pad += b'\x00' * ((56 - (byte_len + 1) % 64) % 64)
    pad += struct.pack(b'>Q', byte_len * 8)
    return pad


plain = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
secretHash = sha1hash(plain)

for key_len in range(1000000):
    decimalHash = int(secretHash, 16)
    fake = b';admin=true'

    glue = get_pad(message, key_len)
    fakeLen = key_len + len(plain) + len(glue) + len(fake)

    a = secretDecimalHash >> 128
    b = (secretDecimalHash >> 96) & 0xffffffff
    c = (secretDecimalHash >> 64) & 0xffffffff
    d = (secretDecimalHash >> 32) & 0xffffffff
    e = secretDecimalHash & 0xffffffff
    h = get_internal_state([a, b, c, d, e])

    sha1 = Sha1Hash(h)
    digest = sha1.digest(b';admin=true', fakeLen)

    shatest = hashlib.sha1()
    shatest.update(plain+fake+glue)
    test = shatest.hexdigest()

    if digest == test:
            print(digest)
    else:
        print('Failed')
