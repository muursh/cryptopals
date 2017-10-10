#challenge 36
import hashlib
import random

#SRP - based on http://en.wikipedia.org/Secure_Remote_Password_protocol

#Both C&S
N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3
I = "username"
p = "password"

#S
salt = random.randint(0, N)
#hash of string and password
xH = hashlib.sha256()
xH.update(str(salt).encode())
xH.update(p.encode())
xH_hex = xH.hexdigest()
#hash as int
x = int(xH_hex, 16)
v = pow(g, x, N)

#like diffie hellman
#C->S
a = random.randint(0, N)
A = pow(g, a, N)
#S->C
b = random.randint(0, N)
B = (k*v + pow(g, b, N))

#Both S&C
uH = hashlib.sha256()
uH.update(str(A).encode())
uH.update(str(B).encode())
uH_hex = uH.hexdigest()
u = int(uH_hex, 16)

#C
S = pow(B - k * pow(g, x, N), a + u * x, N)
#get hash of s
kH = hashlib.sha256()
kH.update(str(S).encode())
kH_hex = kH.hexdigest()

#C->S
#hash of k and salt for verification
sH = hashlib.sha256()
sH.update(str(kH_hex).encode())
sH.update(str(salt).encode())
session = sH.hexdigest()
