# cryptopals challenge 4

import binascii
import re
from itertools import cycle

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
    'u' : 5,
    ' ' : 5
}

def xor(string, key):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(string, cycle(key)))

def score(string):
    score = 0
    for x in string:
        if x in letter_points:
            score += letter_points[x]
    return score 

def get_decrypted(string):
    result = 0  
    for i in range(0,256):
        decoded = xor(string,chr(int(i)))
        if(score(decoded) > result):
            result = score(decoded)
            most_likely_key = i
            message = decoded 
    return (most_likely_key,result,message)

most_likely_mess = ""
max_score = 0
most_likely_key = ""

file = open("challenge4.txt", 'r')
for line in file:
    if line[-1] == '\n':
        line = line[:-1]
    s = binascii.unhexlify(line)
    (curr_key,curr_score,curr_mess) = get_decrypted(s)
    if(curr_score > max_score ):
        most_likely_key = curr_key
        max_score = curr_score
        most_likely_mess = curr_mess
        
print (most_likely_mess)
print chr(most_likely_key)
