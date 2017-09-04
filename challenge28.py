#cryptopals challenge 28

import struct
import binascii

def left_rotation(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

#return the sha1 hash of the input message
#based on the pseudo code from https://en.wikipedia.org/wiki/SHA-1
def sha1(message):
    
    # Initialize variables
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    
    m1 = len(message)
    m2 = m1 * 8
    message += b'\x80'
    
    # append 0 <= k < 512 bits '0', so that the resulting message length is congruent to 448 (mod 512)
    message += b'\x00' * ((56 - (m1 + 1) % 64) % 64)
    
    # append length of message
    message += struct.pack('>Q', m2)

    
    # break message into 512-bit chunks
    for i in range(0, len(message), 64):
        
        w = [0] * 80
        # break chunk into sixteen 32-bit big-endian words w[i], 0<= i <= 15
        for j in range(16):
            w[j] = struct.unpack('>I', message[i + j*4:i + j*4 + 4])[0]
            
        # Extend the sixteen 32-bit words into eighty 32-bit words
        for j in range(16, 80):
            w[j] = left_rotation(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)
    
        # Initialize hash value for this chunk
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        #Main loop
        for i in range(80):
            
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
                
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
                
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
                
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
    
            a, b, c, d, e = ((left_rotation(a, 5) + f + e + k + w[i]) & 0xffffffff, a, left_rotation(b, 30), c, d)
   
        # Add this chunk's hash to result so far
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff 
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
    
    # Produce the final hash value
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

#32d10c7b8cf96570ca04ce37f2a19d84240d3a89 -- expected value from www.functions-online.com/sha1.html
print(sha1(b'abcdefghijklmnopqrstuvwxyz'))
#2fd4e1c67a2d28fced849ee1bb76e7391b93eb12 -- expected value from wikipedia
print(sha1(b'The quick brown fox jumps over the lazy dog'))
