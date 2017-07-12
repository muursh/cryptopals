# cryptopals challenge 3

import array
import re

#most common english letters
letter_points = {
    'e' : 10,
    't' : 10,
    'a' : 10,
    'o' : 10,
    'i' : 10,
    'n' : 10,
    's' : 5,
    'h' : 5,
    'r' : 5,
    'd' : 5,
    'l' : 5,
    'u' : 5
}


def decode(orig, char):
    hex_data = orig.decode('hex')
    byte_arr = array.array('b', hex_data)
    result = [b ^ char for b in byte_arr]
    return "".join("{:c}".format(b) for b in result)


def score(string):
    score = 0
    for x in string:
        if x in letter_points:
            score += letter_points[x]
    return score


def get_decrypted(orig):
    most_likely_mess = ""
    max_score = 0
    most_likely_key = ""
    for i in range(256):
        string = decode(orig, i)
        curr_score = score(string)
        if curr_score > max_score:
            max_score = curr_score
            most_likely_mess = string
            most_likely_key = i
            
    print (most_likely_mess)
    print chr(most_likely_key)


encoded = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
get_decrypted(encoded)
