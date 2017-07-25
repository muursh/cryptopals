#cryptopals challenge 21

#MT19937 Mersenne Twister PRNG
#Psuedocode from https://en.wikipedia.org/wiki/Mersenne_Twister

class MT19937:

    def __init__(self, seed, clonestate=None):
        self.index = 624
        self.mt = [0] * 624
        
        if clonestate is None:
            self.mt[0] = seed
            for i in range(1, 624):
                self.mt[i] = (0x6c078965 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i) & 0xffffffff

        else:
            self.mt = clonestate
            self.index = 0

    def extract(self):
        if self.index >= 624:
            self.twist()
            
        y = self.mt[self.index]
        #constants used for bitshits and bitwise operations from wikipedia
        y = y ^ y >> 11
        #0x9d2c5680 = 2636928640
        y = y ^ y << 7 & 0x9d2c5680
        #0xefc60000 = 4022730752
        y = y ^ y << 15 & 0xefc60000
        y = y ^ y >> 18

        self.index = self.index + 1
        return (y & 0xffffffff)


    def twist(self):
        for i in range(624):
            y = ((self.mt[i] & 0x80000000) + (self.mt[(i + 1) % 624] & 0x7fffffff)) & 0xffffffff
            self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1

            if y % 2 != 0:
                self.mt[i] = self.mt[i] ^ 0x9908b0df
                
        self.index = 0

#test against known seed - 2017 - solutions from http://create.stephan-brumme.com/mersenne-twister/
if __name__ == '__main__':
    
    prng = MT19937(2017)
    for i in range(5):
        print(prng.extract())
