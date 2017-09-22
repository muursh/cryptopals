#cryptopals challenge 30

import os
import struct
from md4 import MD4, get_pad

def get_hash(orig):
    md4 = MD4()
    md4.update(KEY + orig)
    return md4.dgst()


def get_hash_check(orig):
    md4 = MD4()
    md4.update(KEY + orig)
    return md4.dgst()


KEY = b'YELLOW SUBMARINE'
message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
faked = b';admin=true'
mess = struct.unpack('<4I', get_hash(message))

for i in range(10000):
    padding = b'A' * i
    new_key = get_pad(padding + message) + faked
    length = len(new_key) * 8
    fake_mess = new_key[i:]
    md4hash = MD4(mess)
    md4hash.update(faked, length)
    fake_mac = md4hash.dgst()
    test = get_hash_check(fake_mess)
    if test == fake_mac:
        print(fake_mess)
