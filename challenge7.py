# cryptopals challenge 7

from Crypto.Cipher import AES

def decrypt(ciphered, key):
    cipher = AES.new(key, AES.MODE_ECB)
    print cipher.decrypt(ciphered)

key = "YELLOW SUBMARINE"
with open('challenge7.txt', 'r') as f:
    orig = f.read().decode('base64')
print(decrypt(orig,key))
