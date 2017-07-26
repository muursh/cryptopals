#cryptopals challenge 23

from challenge21 import MT19937

def undo(n):
    #undo the number extraction from challenge21 - complete reverse of function
    n = n ^ (n>>18)
    n = n ^ ((n<<15) & 0xefc60000)

    temp = n ^ ((n<<7) & 0x9d2c5680)
    temp = n ^ ((temp<<7) & 0x9d2c5680)
    temp = n ^ ((temp<<7) & 0x9d2c5680)
    temp = n ^ ((temp<<7) & 0x9d2c5680)
    n = n ^ ((temp<<7) & 0x9d2c5680)

    tmp = n ^ (n>>11)
    n = n ^ (tmp>>11)
    
    return n


def get_state(original):
    state = []

    for output in original:
        state.append(undo(output))
    return state


if __name__ == '__main__':
    prng = MT19937(2017)
    original = []

    for i in range(0, 624):
        original.append(prng.extract())

    state = get_state(original)
    cloned_prng = MT19937(seed=2017, clonestate=state)
    cloned = []

    for i in range(0, 624):
       cloned.append(cloned_prng.extract())

    if original == cloned:
        print('PRNG cloned successfully')
    else:
        print('Could not clone prng')
