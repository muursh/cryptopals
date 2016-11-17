# cryptopals challenge 9

def pad(string, padsize):
    padded_size = padsize - (len(string) % padsize)
    if padded_size ==0:
        padded_size = padsize
    return string + chr(padded_size)*padded_size

string = "YELLOW SUBMARINE"
print (pad(string, 20))
