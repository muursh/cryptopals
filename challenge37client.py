#cryptopals chellenge 37 client
import socket
import pickle
import hmac
import hashlib
import os
import Crypto.Cipher
import random

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3
I =  b'username'
p = b'' #password not hardcoded

class Client:
    def __init__(self, network):
        self._network = network.subscribe(self)

    def connect(self):
        self.a = random.randint(0, N-1)
        A = 0
        self.A = A
        self._network.send(self, [0, I, A])

    def receive(self, msg):
        if msg[0] == 1:
            _, salt, B = msg
            uH = hashlib.sha256()
            uH.update(str(self.A).encode())
            uH.update(str(B).encode())
            u = uH.digest()
            xH = hashlib.sha256()
            xH.update(str(salt).encode())
            xH.update(p.encode())
            xH_hex = xH.hexdigest()
            x = int(xH_hex, 16)
            S = 0

            K = hashlib.sha256()
            K.update(S.encode())
            self._network.send(self, [2, hmac256(K, salt)])
        if msg[0] == 3:
            print(msg[1])


def hmac256(key, *items):
    h = hmac.new(key, digestmod='sha256')
    data = b''.join(convert_to_bytes(items))
    h.update(data)
    return h.digest()


class Network:
    def __init__(self, mitm=None):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 4001))
        self._listeners = []

    def subscribe(self, listener):
        self._listeners.append(listener)
        return self

    def send(self, sender, msg):
        serialized = pickle.dumps(msg)
        self.sock.sendto(serialized, ('127.0.0.1', 4000))
        self.listen_once()

    def listen_once(self):
        data, addr = self.sock.recvfrom(1024)
        msg = pickle.loads(data)
        print('rec', msg)
        for l in self._listeners:
            l.receive(msg)

network = Network()
c = Client(network)
c.connect()
            
