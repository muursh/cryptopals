#cryptopals challenge 37 server
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
p = b'password'

class Server:
    def __init__(self, network):
        self._network = network.subscribe(self)
        self._salt = random.randint(0, 1024)
        xH = hashlib.sha256()
        xH.update(str(self._salt).encode())
        xH.update(p)
        xH_hex = xH.hexdigest()
        #hash as int
        x = int(xH_hex, 16)
        self.v = pow(g, x, N)

    def rec(self, msg):
        if msg[0] == 0:
            _, I, A = msg
            b = random.randint(0, N-1)
            B = k * self.v + pow(g, b, N)
            
            uH = hashlib.sha256()
            uH.update(str(A).encode())
            uH.update(str(B).encode())
            uH_hex = uH.hexdigest()
            #hash as int
            u = int(uH_hex, 16)
            S = pow(A*pow(self.v, u, N), b, N)
            self.K = hashlib.sha256()
            self.K.update(S.encode())
            self._network.send(self, [1, self._salt, B])
        if msg[0] == 2:
            _, theirs = msg
            h = hmac.new(key, digestmod='sha256')
            h.update(self.K)
            h.update(self._salt)
            mine = h.digest()
            if theirs == mine:
                print ("ok")
            else:
                print("nack")
            self._network.send(self, [3, theirs==mine])

class Network:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 4000))
        self._listeners = []

    def subscribe(self, listener):
        self._listeners.append(listener)
        return self

    def send(self, sender, msg):
        serialized = pickle.dumps(msg)
        self.sock.sendto(serialized, ('127.0.0.1', 4001))

    def listen(self):
        while True:
            data, addr = self.sock.recvfrom(1024)
            msg = pickle.loads(data)
            for l in self._listeners:
                l.receive(msg)

network = Network()
server = Server(network)
network.listen()
