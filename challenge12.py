# cryptopals challenge 12
from base64 import b64decode
from random import randint
from string import printable
from Crypto.Cipher import AES

key = "".join([chr(randint(0, 255)) for byte in range(16)])
orig = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

def decrypt_ecb(string, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(string)

def encrypt_ecb(string, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(string)

def encrypt_blackbox(data):
    decoded = b64decode(orig)
    string = data + decoded
    padding = "\x00" * (16 - len(string) % 16)
    string += padding
    return encrypt_ecb(string, key)

def len_diff(string):
    length = 0
    orig_len = len(encrypt_blackbox(string))
    while True:
        message = string + "\x00" * length
        new_len = len(encrypt_blackbox(message))
        if new_len != orig_len:
            return length
        else:
            length += 1

def get_len():
    length = len_diff("\x00" * len_diff(""))
    return length

def bruteforce(encrypted_len):
    secret_len = len(encrypt_blackbox(""))
    result = []
    block_num = secret_len / encrypted_len - 1
    for i in range(1, secret_len + 1):
        data = "\x00" * (secret_len - i)
        encrypted = encrypt_blackbox(data)
        blocks = partblock(encrypted, encrypted_len)
        ref = blocks[block_num]
        result.append(brute_char(data, result, block_num, ref))
    return "".join(result)

def brute_char(data, current_result, block_num, ref):
    for character in printable:
        brute_data = data + "".join(current_result) + character
        encrypted = encrypt_blackbox(brute_data)
        blocks = partblock(encrypted, encrypted_len)
        result_block = blocks[block_num]
        if ref == result_block:
            return character
    return " "

def partblock(orig, size):
    return [orig[i * size:(i + 1) * size] for i in range(len(orig) / size)]

encrypted_len = get_len()
print(encrypted_len)
message = bruteforce(encrypted_len)
print(message)
