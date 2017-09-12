#sha1 implementation for challenge 29 - easier to use than challenge 28 code

class Sha1Hash(object):

        #used for length extension attack
	def __init__(self, initial_h=None):
		self._h = initial_h

	def left_rotation(self, n, bits):
		return ((n << bits) | (n >> (32 - bits))) & 0xffffffff

        #64 bit chunk
	def _processChunk(self, chunk):
		assert len(chunk) == 64

		words = [0] * 80
		#split into 4 byte chunks
		for i in range(16):
			words[i] = struct.unpack(b'>I', chunk[i*4:i*4 + 4])[0]

		for i in range(16, 80):
			words[i] = self.left_rotation(
				words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16], 1)
                #init hash for this chunk
		a = self._h[0]
		b = self._h[1]
		c = self._h[2]
		d = self._h[3]
		e = self._h[4]

                #main loop
		for i in range(0, 80):
			if i >= 0 and i <= 19:
				f = (b & c) | ((~b) & d)
				k = 0x5A827999
			elif i >= 20 and i <= 39:
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			elif i >= 40 and i <= 59:
				f = (b & c) | (b & d) | (c & d) 
				k = 0x8F1BBCDC
			else:
				f = b ^ c ^ d
				k = 0xCA62C1D6

			tmp = ((self.left_rotation(a, 5) + f + e + k + words[i])
				    & 0xffffffff)
			e = d
			d = c
			c = self.left_rotation(b, 30)
			b = a
			a = tmp
                #add this chunk's hsh to result so far
		self._h[0] = (self._h[0] + a) & 0xffffffff
		self._h[1] = (self._h[1] + b) & 0xffffffff
		self._h[2] = (self._h[2] + c) & 0xffffffff
		self._h[3] = (self._h[3] + d) & 0xffffffff
		self._h[4] = (self._h[4] + e) & 0xffffffff

        #return sha1 for orig allow fake length for length attacks
	def digest(self, orig, len_attack=None):
                
		if self._h is None:
                        #initialize vars
			self._h = [
				0x67452301,
				0xEFCDAB89,
				0x98BADCFE,
				0x10325476,
				0xC3D2E1F0,
			]

		message = orig
		byteLength = len(message) if len_attack is None else len_attack

                #aapend '1'
		message += b'\x80'
		#append 0<= k < 512 bbit '0' such message length is congruent to -64:448 )mod512)
		message += b'\x00' * ((56 - (byteLength + 1) % 64) % 64)
		message += struct.pack(b'>Q', byteLength * 8)

		for i in range(0, int(len(message) / 64)):
			chunk = message[i * 64 : (i+1) * 64]
			self._processChunk(chunk)
                #prodcut final hash value
		digest = (self._h[0] << 128) | (self._h[1] << 96) | (self._h[2] << 64) | (self._h[3] << 32) | self._h[4]
                #return final hash
		return '%x' % digest


def sha1hash(message):
	h = Sha1Hash()
	return h.digest(message)
