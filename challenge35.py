#cryptopals challenge 35
import random
from hashlib import sha1
from Crypto.Cipher import AES

#MITM attack
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
#g = 2
g = p-1
#g = p

#A sends (p, g) -> MITM
#MITM sends ack -> A

#A sends (a, A) -> MITM
a = random.randint(0,p)
A = pow(g, a, p)

#MITM -> B
a_f = g

#B sends (b, B) -> MITM
b = random.randint(0, p)
B = pow(g, b, p)

#MITM -> A
b_f = g

#A sends AES cipher ->  MITM
sA = pow(b_f, a, p)
sA_h = sha1()
sA_h.update(str(sA).encode())
sA_hash = sA_h.hexdigest()
m_orig = b'aaaaaaaaaaaaaaaa'
iv = b'\x00' * AES.block_size
c = AES.new(key=sA_hash[:16], mode=AES.MODE_CBC, IV=iv)
cipher1 = c.encrypt(m_orig)

#MITM forwards -> B
m_h = sha1()
m_h.update(str(0).encode())
M_hash = m_h.hexdigest()
msg_m = c.decrypt(cipher1)

#B sends to MITM
sB = pow(a_f, a, p)
sB_h = sha1()
sB_h.update(str(sB).encode())
sB_hash = sB_h.hexdigest()
m2 = c.decrypt(cipher1)
c2 = AES.new(key=sB_hash[:16], mode=AES.MODE_CBC, IV=iv)
cipher2 = c2.encrypt(m2)

#MITM -> A
msg_final = c.decrypt(cipher2)

print(msg_final)
print(m_orig)
