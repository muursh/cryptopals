#cryptopals challenge 38
import hashlib
import hmac
import random
from challenge37server import Server
from challenge37client import Client


N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3
I = b'username'
P = b'password'

class MITM:
    passwords = []
    #file filled with 100 most common passwords and a few random phrases
    with open('passwords.txt') as f:
        for p in f:
            passwords.append(p)

    def intercept(self, sender, msg):
        if msg[0] == 0:
            _, _, self.A = msg

        if msg[0] == 1:
            n, salt, old_b = msg
            return [n, b'', 2]

        if msg[0] == 2:
            _, mac = msg
            print("MAC", mac)

            uH = hashlib.sha256()
            uH.update(str(self.A).encode())
            uH_hex = uH.hexdigest()
            u = int(uH_hex, 16)
            salt = b''
            for pw in self.passwords:
                xH = hashlib.sha256()
                xH.update(str(pw).encode())
                xH_hex = xH.hexdigest()
                x = int(xH_hex, 16)
                S = (self.A * pow(2, u * x, N)) % N
                K = hashlib.sha256()
                K.update(S.encode())
                if mac == hmac256(K, salt):
                    print(pw)
                    break
            else:
                print("nack")

        return msg


def hmac256(key, *items):
    h = hmac.new(key, digestmod='sha256')
    data = b''.join(convert_to_bytes(items))
    h.update(data)
    return h.digest()


class Network:
    def __init__(self, MITM=None):
        self._listeners = []
        self._mitm = MITM

    def subscribe(self, listener):
        self._listeners.append(listener)
        return self

    def send(self, sender, msg):
        if self._mitm:
            msg = self._mitm.intercept(sender, msg)
        for listener in self._listeners:
            if listener != sender:
                listener.receive(msg)
        

MITM = MITM()
network = Network(MITM=MITM)
c = Client(network)
s = Server(network)
c.connect()
