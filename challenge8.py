import itertools

def calc(line):
    sets = [line[i:i+32] for i in range(0, len(line), 32)] 
    pairs = itertools.combinations(sets, 2) 
    identical = 0 
    for p in pairs: 
        if p[0] == p[1]: 
            identical += 1 
    return identical 

with open('challenge8.txt') as f:
    for line in f:
        count = calc(line)
        if count > 0:
            print(count)
            print(line)
