#cryptopals challenge 22

from challenge21 import MT19937
import random
import time

def gen_num():
    time.sleep(random.randint(40, 1000))
    seed = int(time.time())
    prng = MT19937(seed)
    time.sleep(random.randint(40, 1000))
    return seed, prng.extract()


def break_seed(n):
    seed_guess = int(time.time())
    while seed_guess > 0:
        if (MT19937(seed_guess).extract() == n):
            return seed_guess
        else:
            seed_guess -= 1

orig_seed, rand_num = gen_num()
seed_crack = break_seed(rand_num)

if orig_seed == seed_crack:
    print (seed_crack)
    print (time.strftime("%H:%M:%S", time.gmtime(seed_crack)))

else:
    print ('Seed cracking failed.')
