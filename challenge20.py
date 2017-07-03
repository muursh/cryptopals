#cryptopals challenge 20

from base64 import b64decode
from functools import reduce

# Numbers from wikipedia for letters. Punctuation frequencies are a wild guess
# https://en.wikipedia.org/wiki/Letter_frequency
letter_points = {
    'a': 8.167,
    'b': 1.492,
    'c': 2.782,
    'd': 4.253,
    'e': 12.702,
    'f': 2.228,
    'g': 2.015,
    'h': 6.094,
    'i': 6.966,
    'j': 0.153,
    'k': 0.772,
    'l': 4.025,
    'm': 2.406,
    'n': 6.749,
    'o': 7.507,
    'p': 1.929,
    'q': 0.095,
    'r': 5.987,
    's': 6.327,
    't': 9.056,
    'u': 2.758,
    'v': 0.978,
    'w': 2.360,
    'x': 0.150,
    'y': 1.974,
    'z': 0.074,
    ' ': 20.00,
    '.': 5.000,
    ',': 5.000,
    '?': 2.000,
    '!': 2.000,
}

str_xor = lambda b1, b2: bytes(x ^ y for x, y in zip(b1, b2))

nonce = (0).to_bytes(8, 'little')
blocksize = 16

def score(char):
        score = 0
        letter = (chr(char))
        if letter in letter_points:
            score += letter_points[letter]
        return score

keystream = b''

with open('challenge20.txt', 'r') as file:
    ciphers = [b64decode(line) for line in file]

for i in range(len(max(ciphers, key=len))):
    maxscore = (0, 0, b"")
    for j in range(255):
        deciphered_guess = bytes(c[i] ^ j for c in ciphers if len(c) > i)
        curr_score = reduce(lambda total, x: score(x) + total, deciphered_guess, 0)
        maxscore = max(maxscore, (curr_score, j))
    keystream += bytes([maxscore[1]])

for c in ciphers:
    print(str_xor(keystream, c))
