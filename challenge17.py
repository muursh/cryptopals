# Cryptopals challenge 17

from os import urandom
import random
from Crypto.Cipher import AES

inputs = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
          'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
          'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
          'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
          'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
          'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
          'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
          'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
          'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
          'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

key = urandom(16)
iv = urandom(16)
block_size = 16


def cbc_encrypt(plain_text, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = pad(plain_text, block_size)
    cipher_text = cipher.encrypt(padded_text)
    return cipher_text.encode('hex')


def cbc_decrypt(cipher_text, key, iv):
    cipher_text = cipher_text.decode('hex')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(cipher_text)


def pad(plain_text, block_size):
    final_block_length = len(plain_text) % block_size
    padding_needed = block_size - final_block_length
    hex_escape = chr(padding_needed)
    return plain_text + hex_escape * padding_needed


def unpad(plain_text, block_size):
    last_chr = plain_text[-1]
    if ord(last_chr) < block_size:
        return plain_text[:len(plain_text) - ord(last_chr)]
    else:
        return plain_text


def get_cipher_text():
    s = random.choice(inputs)
    cipher_text = cbc_encrypt(s, key, iv)
    return cipher_text


def padding_valid(hex_cipher_text):
    pt_padded = cbc_decrypt(hex_cipher_text, key, iv)
    return valid_padding(pt_padded, block_size)


def valid_padding(plain_text, block_size):
    last_chr = plain_text[-1]
    if ord(last_chr) <= block_size and ord(last_chr) > 0:
        t_list = list(plain_text)
        c = 0
        while c < ord(last_chr):
            if ord(t_list[-1]) != ord(last_chr):
                return False
            t_list.pop(-1)
            c += 1
        return ''.join(t_list)
    else:
        return False


def get_cipher(input_text):
    plain_text = input_text
    cipher_text = cbc_encrypt(plain_text, key, iv)
    return cipher_text


def is_admin(hex_cipher_text):
    plain_text = cbc_decrypt(hex_cipher_text, key, iv)
    tuples = [x.split('=') for x in plain_text.split(';')]
    for key, value in tuples:
        if key == 'admin' and value == 'true':
            return True
    return False


def xor(s1, s2):
    return ''.join([chr(ord(x) ^ ord(y)) for x, y in zip(s1, s2)])


def get_blocks(text):
    num_blocks = len(text) / block_size
    blocks = [text[block_size * i:block_size * (i + 1)] for i in range(num_blocks)]
    return blocks


def get_next_char(cipher_text, known_chars):
    blocks = get_blocks(cipher_text)
    blocks_filled = len(known_chars) // block_size
    rem = blocks[:len(blocks) - blocks_filled]
    overflow = len(known_chars) % block_size
    extra_chars = known_chars[:overflow]

    target_padding_number = len(extra_chars) + 1
    target = list(rem[-2])
    for index, char in enumerate(extra_chars):
        block_index = block_size - overflow + index
        target_ct_char = target[block_index]
        target[block_index] = chr(ord(target_ct_char) ^ ord(char) ^ target_padding_number)

    target_index = block_size - overflow - 1
    orig = ord(target[target_index])
    for z in range(255):
        target[target_index] = chr(orig ^ z ^ target_padding_number)
        new_block = ''.join(target)
        rem[-2] = new_block
        new_ct = ''.join(rem).encode('hex')
        if overflow == 0:
            if padding_valid(new_ct) and z != target_padding_number:
                return chr(z) + known_chars
        else:
            if padding_valid(new_ct):
                return chr(z) + known_chars


cipher_text = get_cipher_text().decode('hex')
length = len(cipher_text)
cipher_text = iv + cipher_text
known_chars = ''
for i in range(length):
    known_chars = get_next_char(cipher_text, known_chars)
for string in inputs:
    print string.decode('base64')[6:]  # strip leading number

