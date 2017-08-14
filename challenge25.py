#cryptopals challenge 25

from os import urandom
from base64 import b64decode
from Crypto.Cipher import AES

#return new block block cipher
def edit(cipher, off, new):
    m = bytearray(run_ctr(randkey, 0, cipher))
    m[off:len(new)] = new
    return run_ctr(randkey, 0, m)

#ctr block mode
def run_ctr(k, block, m):
    cipher = AES.new(k, AES.MODE_ECB)
    n = nonce + block.to_bytes(8, 'little')
    blk = xor(m, cipher.encrypt(n))
    r = min(len(m), 16)
    return blk + run_ctr(k, block+1, m[r:]) if r else blk


key = b'YELLOW SUBMARINE'
randkey = urandom(16)
cipher = AES.new(key, AES.MODE_ECB)
nonce = urandom(8)
xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))

with open('challenge25.txt') as file:
    plain_text = b64decode(file.read())

plain = cipher.decrypt(plain_text)
original = run_ctr(randkey, 0, plain)
output = edit(original, 0, original)
print(output.decode("utf-8"))
