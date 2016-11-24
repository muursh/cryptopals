# cryptopals challenge 10

from Crypto.Cipher import AES

def xor(a, b):
    return "".join([chr(ord(x) ^ ord(y)) for x, y in zip(a, b)])

def decrypt_ecb(string, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(string)

def encrypt_ecb(string, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(string)

def partblock(input_data, size):
    return [input_data[i * size:(i + 1) * size] for i in range(len(input_data) / size)]

def decrypt(input_data, key, padding):
    ans = []
    pad = padding
    for block in partblock(input_data, len(padding)):
        decrypted_ecb = decrypt_ecb(block, key)
        xored = xor(decrypted_ecb, pad)
        pad = block
        ans.append(xored)
    return "".join(ans)

def encrypt(input_data, key, padding):
    ans = []
    pad = padding
    for block in partblock(input_data, len(padding)):
        xored = xor(block, pad)
        encrypted_ecb = encrypt_ecb(xored, key)
        pad = encrypted_ecb
        ans.append(encrypted_ecb)
    return "".join(ans)

with open('challenge10.txt', 'r') as f:
    orig = f.read().decode('base64')
    key = "YELLOW SUBMARINE"
    print(decrypt(orig, key, "\x00" * 16))
    test = encrypt("kotykotykotykoty", "keyskeyskeyskeys", "\x00" * 16)
    
print(decrypt(test, "keyskeyskeyskeys", "\x00" * 16))
