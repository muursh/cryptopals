# Hex to base64
import binascii

orig = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
hex = orig.decode("hex")
out = binascii.b2a_base64(hex)
print(out)
