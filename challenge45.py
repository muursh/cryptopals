#cryptopals challenge 45

def egcd(a, b):
    if b == 0:
        return (1, 0)
    else:
        q = a // b;
        r = a % b;
        (s, t) = egcd(b, r)
        return (t, s - q * t)


def invmod(a, N):
    (x, y) = egcd(a, N)
    return x % N


#params given in challenge
p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
zero = 0
g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
x = 8675309
y = pow(g, x, p)
pp = (p + 1)
r = y%q
s = r


def dsa0(hashed_text):
    x = 8675309
    k = 24601
    y = pow(zero, x, p)
    r = pow(zero, k, p) % q
    s = (invmod(k, p) * (hashed_text + x*r)) % q
    return (y,r,s)


def isCorrect_dsa0(y, r, s, hashed_text):
    w = invmod(s, q)
    u1 = (hashed_text * w) % q
    u2 = (r*w) % q
    v = (pow(zero, u1, p) * pow(y, u2, p) % p) % q
    return (v == r)


def isCorrect_dsa1(y, r, s, hashed_text):
    w = invmod(s, q)
    u1 = (hashed_text * w) % q
    u2 = (r*w) % q
    v = (pow(pp, u1, p) * pow(y, u2, p) % p) % q
    return (v == r)

 
def get_dsa0():
    hashed_text = 0x0102030405060708091011121314151617181920
    (y, r, s) = dsa0(hashed_text)
    assert(r == 0)
    assert(isCorrect_dsa0(y, r, s, hashed_text))
    assert(isCorrect_dsa0(13, 0, 23423423432, hashed_text))
    assert(isCorrect_dsa0(32432423, 0, 342423432423, 0x3daf05ce546d1))
    return True
 
 
def get_dsa1():
    h1 = 0xe02aa1b106d5c7c6a98def2b13005d5b84fd8dc8 #sha1(b'Hello, world')
    h2 = 0xdc519a4510e5e848e1f77da409fa1410c84d43fb #sha1(b'Goodbye, world')
    assert(isCorrect_dsa1(r, r, s, h1))
    assert(isCorrect_dsa1(r, r, s, h2))
    return True


if(get_dsa1() == True and get_dsa0() == True):
    print ("Done")
else:
    print ("Failed")
