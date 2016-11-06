# cryptopals challenge 6

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
    'u' : 5
}

def hamm(str1, str2):        
        diffs = 0
        for ch1, ch2 in zip(str1, str2):
                if ch1 != ch2:
                        diffs += 1
        return diffs
    
def score(string):
    score = 0
    for x in string:
        if x in letter_points:
            score += letter_points[x]
    return score

def xor(string, key):
    return ''.join(chr(ord(x) ^ key) for x in string)

def key_guesser(keysize):
    num = (len(orig) / keysize)
    sum = 0
    for i in range(num - 1):
        a = orig[i * keysize: (i+1) * keysize]
        b = orig[(i+1) * keysize: (i+2) * keysize]
        sum += hamm(a, b)
    sum /= float(num)
    sum /= float(keysize)
    return sum

with open('challenge6.txt', 'r') as f:
    orig = f.read().decode('base64')

most_likely_size = min(range(2, 41), key=key_guesser)
print "Most likely key length = ", most_likely_size

key = [None]*most_likely_size

for i in range(most_likely_size):
    d = orig[i::most_likely_size]
    key[i] = max(range(256), key=lambda k: score(xor(d, k)))

key = ''.join(map(chr, key))

print "Most likely key = ", repr(key)
print "-----------------------------------------------------------------"
print ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(orig, cycle(key)))
