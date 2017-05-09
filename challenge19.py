#cryptopals challenge 19

from base64 import b64decode
from Crypto.Cipher import AES
import os
from functools import reduce

original_strings = [
    b"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
    b"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
    b"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
    b"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
    b"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
    b"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    b"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
    b"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    b"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
    b"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
    b"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
    b"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
    b"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
    b"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
    b"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
    b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    b"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
    b"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
    b"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
    b"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
    b"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
    b"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
    b"U2hlIHJvZGUgdG8gaGFycmllcnM/",
    b"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
    b"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
    b"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
    b"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
    b"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
    b"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
    b"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
    b"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
    b"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
    b"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
    b"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
    b"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
    b"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
    b"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
    b"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
    b"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
    b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
]

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


def encrypt(key, counter, plain):
    cipher = AES.new(key, AES.MODE_ECB)
    n = nonce + counter.to_bytes(8, 'little')
    block = str_xor(plain, cipher.encrypt(n))
    r = min(len(plain), 16)
    if r > 0:
        return block + encrypt(key, counter + 1, plain[r:])
    else:
        return block


random_key = os.urandom(16)
ciphers = [encrypt(random_key, 0, b64decode(m)) for m in original_strings]

keystream = b''

for i in range(len(max(ciphers, key=len))):
    maxscore = (0, 0, b"")
    for j in range(255):
        deciphered_guess = bytes(c[i] ^ j for c in ciphers if len(c) > i)
        curr_score = reduce(lambda total, x: score(x) + total, deciphered_guess, 0)
        maxscore = max(maxscore, (curr_score, j, deciphered_guess))
    keystream += bytes([maxscore[1]])

for x in ciphers:
    print(str_xor(keystream, x))

