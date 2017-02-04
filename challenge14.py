# Cryptopals challenge 14

from os import urandom
from random import randint
from Crypto.Cipher import AES

prepend_string = urandom(randint(1, 100))
#print len(prepend_string)
key = "".join([chr(randint(0, 255)) for byte in range(16)])
orig = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
block_size = 16


def encrypt_ecb(string, key):
    cipher = AES.new(key, AES.MODE_ECB)
    cipher_text = cipher.encrypt(pks_pad(string, block_size))
    return cipher_text.encode('hex')


def decrypt_ecb(string, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plain_text_padded = cipher.decrypt(string.decode('hex'))
    return pks_unpad(plain_text_padded, block_size)


def brute_cipher(attacker_controlled):
    plaintext = prepend_string + attacker_controlled + orig.decode('base64')
    return encrypt_ecb(plaintext, key).decode('hex')


def pks_pad(plain_text, block_size):
    final_block_length = len(plain_text) % block_size
    padding_needed = block_size - final_block_length
    hex_escape = chr(padding_needed)
    return plain_text + hex_escape * padding_needed


def pks_unpad(plain_text, block_size):
    last_chr = plain_text[-1]
    if ord(last_chr) < block_size:
        return plain_text[:len(plain_text) - ord(last_chr)]
    else:
        return plain_text


def len_diff():
    length = 0
    while True:
        block = 'b' + 15 * ' '
        temp = 'a' * length + block * 2
        cipher_text = brute_cipher(temp)

        num_blocks = len(cipher_text) // 16
        for j in range(num_blocks):
            block = cipher_text[16 * j:16 * (j + 1)]
            next_block = cipher_text[16 * (j + 1):16 * (j + 2)]
            if block == next_block:
                return (16 - length) + (j - 1) * 16
        length += 1


def brute_next_char(encrypted_len, block_size, message):
    temp_char = 'a' * (block_size - encrypted_len % block_size)
    message_len = block_size - 1 - (len(message) % block_size)
    current_input = temp_char + 'a' * message_len
    block_number = len(message) / block_size + encrypted_len / block_size + 1
    block_start, block_finish = (block_number * block_size, block_number * block_size + block_size)
    output = brute_cipher(current_input)[block_start:block_finish]
    for i in range(1, 255):
        test_input = current_input + message + chr(i)
        cipher_text = brute_cipher(test_input)[block_start:block_finish]
        if cipher_text == output:
            return chr(i)
    return False


encrypted_len = len_diff()
message = ''
next_char = 'a'
while next_char:
    next_char = brute_next_char(encrypted_len, block_size, message)
    if next_char:
        message += next_char
print message

