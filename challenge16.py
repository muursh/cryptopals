#Cryptopals challenge 16

from os import urandom
from Crypto.Cipher import AES

RAND_KEY = urandom(16)
iv = urandom(16)


def xor(s1, s2):
    return ''.join([chr(ord(x) ^ ord(y)) for x, y in zip(s1, s2)])


def encrypt(string, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = pad(string, 16)
    cipher_text = cipher.encrypt(padded_text)
    return cipher_text.encode('hex')


def decrypt(hex_cipher_text, key, iv):
    cipher_text = hex_cipher_text.decode('hex')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text_padded = cipher.decrypt(cipher_text)
    return unpad(plain_text_padded, 16)


def final_string(string):
    s1 = "comment1=cooking%20MCs;userdata="
    s2 = ";comment2=%20like%20a%20pound%20of%20bacon"
    final = ''.join(string.split(';'))
    final = ''.join(final.split('='))
    return s1 + final + s2


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


def is_valid_padding(plain_text, block_size):
    final_char = plain_text[-1]
    if ord(final_char) < block_size:
        t_list = list(plain_text)
        c = 0
        while c < ord(final_char):
            if ord(t_list[-1]) != ord(final_char):
                print ("issue")
                return False
            t_list.pop(-1)
            c += 1
        return ''.join(t_list)
    else:
        return plain_text


def get_cipher(string):
    plain_text = final_string(string)
    cipher_text = encrypt(plain_text, RAND_KEY, iv)
    return cipher_text


def is_admin(cipher_string):
    plain_text = decrypt(cipher_string, RAND_KEY, iv)
    tuples = [x.split('=') for x in plain_text.split(';')]
    for key, value in tuples:
        if key == 'admin':
            return True
    return False


user_input = chr(0) * 32
cipher = get_cipher(user_input).decode('hex')
block = cipher[32:48]
ans = ';admin=true;' + chr(0) * (16 - len(';admin=true;'))
block_b = xor(ans, block)
cipher_b = cipher[:32] + block_b + cipher[48:]

print is_admin(cipher_b.encode('hex'))

