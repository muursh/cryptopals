# cryptopals challenge 5

import binascii
from itertools import cycle

def xor(string, key):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(string, cycle(key)))

message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = "ICE"
encoded = xor(message,key)
output = binascii.b2a_hex(encoded)
print(output)
