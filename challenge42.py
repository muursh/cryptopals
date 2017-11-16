#cryptopals challenge 42
from hashlib import sha256
from Crypto.Util.number import getPrime

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b%a,a)
    return (g, x - (b//a) * y, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x%m

    
def cuberoot(n, a):
    u = a
    s = a+1
    while u < s:
        s = u
        t =(n-1) * s + a // pow(s, n-1)
        u = t  // n
    return s


def get_sig(mess, d, n):
    mess_hash = sha256(mess).digest()
    padd = b'\1\1' + b'\xff' * (128-35) + b'\xaa'
    sig_int = int.from_bytes(padd+mess_hash, 'big')
    return pow(sig_int, d, n)


def verify_sig(e, n, sig, mess):
    int_block = pow(signature, e, n)
    block = int_block.to_bytes(128, 'big')
    hash_start = block.index(b'\xff\xaa')
    sig_hash = block[hash_start+2:hash_start+34]
    real_hash = hashlib.sha256(msg).digest()
    print(real_hash == sig_hash)


#Generate RSA params
e = 3
p = getPrime(8)
q = getPrime(8)
n = p*q
d = modinv(e, (p-1)*(q-1))


orig = b'hi mom'
orig_sig = getsig(orig)

orig_hash = sha256(mess).digest()
fake_sig = b'\1\1\xff\xaa' + orig_hash + b'\x80' * (128-36)
fake_sig_int = int.from_bytes(fake_sig, 'big')
root = cuberoot(fake_sig_int, 3)
verify_sig(e, n, root, orig)

