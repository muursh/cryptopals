# Cryptopals challenge 2

string = int("1c0111001f010100061a024b53535009181c", 16)
key = int("686974207468652062756c6c277320657965", 16)
print "%X" % (string^key)
