#cryptopals implementation of md4 

import binascii

def left_rot(n, b):
	return ((n << b) | ((n & 0xffffffff) >> (32 - b))) & 0xffffffff

def F(x, y, z):
	return x & y | ~x & z

def G(x, y, z):
	return x & y | x & z | y & z

def H(x, y, z):
	return x ^ y ^ z

def FF(a, b, c, d, k, s, X):
	return left_rot(a + F(b, c, d) + X[k], s)

def GG(a, b, c, d, k, s, X):
	return left_rot(a + G(b, c, d) + X[k] + 0x5a827999, s)

def HH(a, b, c, d, k, s, X):
	return left_rot(a + H(b, c, d) + X[k] + 0x6ed9eba1, s)

def get_pad(msg, fakedlen=0):
	n = len(msg)
	bit_len = fakedlen or n * 8
	index = n & 0x3f
	pad_len = 120 - index
	if index < 56:
		pad_len = 56 - index
	padding = b'\x80' + b'\x00' * 63
	suffix = fakedlen.to_bytes(8, 'little', signed=False)
	padded_msg = msg + padding[:pad_len] + suffix
	return padded_msg

class MD4:
	def __init__(self, a=0, b=0, c=0, d=0):
		self.A = a or 0x67452301
		self.B = b or 0xefcdab89
		self.C = c or 0x98badcfe
		self.D = d or 0x10325476

	def update(self, orig, fakedlen=0):
		msg_bytes = get_pad(orig, fakedlen)
		for i in range(0, len(msg_bytes), 64):
			self.hash(msg_bytes[i:i+64])

	def hash(self, block):
		a, b, c, d = self.A, self.B, self.C, self.D
        		        
		x = []
		for i in range(0, 64, 4):
			x.append(int.from_bytes(block[i:i+4], 'little', signed=False))

		a = FF(a, b, c, d,  0,  3, x)
		d = FF(d, a, b, c,  1,  7, x)
		c = FF(c, d, a, b,  2, 11, x)
		b = FF(b, c, d, a,  3, 19, x)
		a = FF(a, b, c, d,  4,  3, x)
		d = FF(d, a, b, c,  5,  7, x)
		c = FF(c, d, a, b,  6, 11, x)
		b = FF(b, c, d, a,  7, 19, x)
		a = FF(a, b, c, d,  8,  3, x)
		d = FF(d, a, b, c,  9,  7, x)
		c = FF(c, d, a, b, 10, 11, x)
		b = FF(b, c, d, a, 11, 19, x)
		a = FF(a, b, c, d, 12,  3, x)
		d = FF(d, a, b, c, 13,  7, x)
		c = FF(c, d, a, b, 14, 11, x)
		b = FF(b, c, d, a, 15, 19, x)

		a = GG(a, b, c, d,  0,  3, x)
		d = GG(d, a, b, c,  4,  5, x)
		c = GG(c, d, a, b,  8,  9, x)
		b = GG(b, c, d, a, 12, 13, x)
		a = GG(a, b, c, d,  1,  3, x)
		d = GG(d, a, b, c,  5,  5, x)
		c = GG(c, d, a, b,  9,  9, x)
		b = GG(b, c, d, a, 13, 13, x)
		a = GG(a, b, c, d,  2,  3, x)
		d = GG(d, a, b, c,  6,  5, x)
		c = GG(c, d, a, b, 10,  9, x)
		b = GG(b, c, d, a, 14, 13, x)
		a = GG(a, b, c, d,  3,  3, x)
		d = GG(d, a, b, c,  7,  5, x)
		c = GG(c, d, a, b, 11,  9, x)
		b = GG(b, c, d, a, 15, 13, x)

		a = HH(a, b, c, d,  0,  3, x)
		d = HH(d, a, b, c,  8,  9, x)
		c = HH(c, d, a, b,  4, 11, x)
		b = HH(b, c, d, a, 12, 15, x)
		a = HH(a, b, c, d,  2,  3, x)
		d = HH(d, a, b, c, 10,  9, x)
		c = HH(c, d, a, b,  6, 11, x)
		b = HH(b, c, d, a, 14, 15, x)
		a = HH(a, b, c, d,  1,  3, x)
		d = HH(d, a, b, c,  9,  9, x)
		c = HH(c, d, a, b,  5, 11, x)
		b = HH(b, c, d, a, 13, 15, x)
		a = HH(a, b, c, d,  3,  3, x)
		d = HH(d, a, b, c, 11,  9, x)
		c = HH(c, d, a, b,  7, 11, x)
		b = HH(b, c, d, a, 15, 15, x)

		self.A = (self.A + a) & 0xffffffff
		self.B = (self.B + b) & 0xffffffff
		self.C = (self.C + c) & 0xffffffff
		self.D = (self.D + d) & 0xffffffff

	def digest(self):
		return binascii.hexlify(self.A.to_bytes(4, 'little', signed=False) + self.B.to_bytes(4, 'little', signed=False) + self.C.to_bytes(4, 'little', signed=False) + self.D.to_bytes(4, 'little', signed=False)).decode('ascii')
