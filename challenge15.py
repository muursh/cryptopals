# Cryptopals challenge 15

def checkpadding(string):
    final = string[-1]
    finalval = ord(final)

    if len(set(map(ord, string[-finalval:]))) == 1:
        return True
    else:
        return False

print (checkpadding("ICE ICE BABY\x04\x04\x04\x04"))
print (checkpadding("ICE ICE BABY\x05\x05\x05\x05"))
