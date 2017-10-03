#cryptopals challenge 32

import hashlib
import hmac
import time

#use hashlib implemenation
def comp(a, b):
    for x in range(len(a)):
        if a[x] != b[x]:
            return False
        time.sleep(0.05)
    return True


def get_hash(orig):
    h = hmac.new(key=b'YELLOW SUBMARINE', digestmod=hashlib.sha1)
    h.update(orig)
    return h.digest()


def is_same(a, b):
    orig = get_hash(a)
    return comp(orig, b)


message = b'abc'
orig = get_hash(message)
print(orig)

faked = b''

for i in range(20):
    time_max = 0
    b_max = -1
    
    for byte in range(256):
        miss = 20 - i - 1
        sig = faked + bytes([byte]) + b'\x00'*miss
        start = time.time()
        match = is_same(message, sig)
        end = time.time()

        if match:
            print(sig)
            break

        if ((end-start)*1000) >= (50 * (i+1)):
            time_max = ((end-start)*1000)
            b_max = byte

     faked += bytes([b_max])       

print(faked)
