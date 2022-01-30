#!/usr/bin/env python3

import os

def onebits(x):
    '''
    Return the count of '1' bits in the int x
    '''
    n = 0
    while x != 0:
        n += 1
        x = x & (x-1)
    return n

def hamming(b1, b2):
    '''
    Return the hamming distance of the two byte objects
    '''
    return sum([onebits(x^y) for x,y in zip(b1,b2)])

def randbytes(n):
    '''
    Return a randomly populated bytes object of length 'n'.
    '''
    return os.urandom(n)

class mt19937:
    def __init__(self, seed = 5489):
        self.w = 32
        self.n = 624
        self.m = 397
        self.r = 31
        self.a = 0x9908B0DF
        self.u = 11
        self.d = 0xFFFFFFFF
        self.s = 7
        self.b = 0x9D2C5680
        self.t = 15
        self.c = 0xEFC60000
        self.l = 18
        self.f = 1812433253

        self.mt = self.n * [0]
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = (~self.lower_mask) & ((1 << self.w) - 1)

        self.index = self.n
        self.mt[0] = seed
        for i in range(1, self.n):
            v = (self.f * (self.mt[i-1] ^ (self.mt[i-1] >> (self.w-2))) + i)
            v &= ((1 << self.w) - 1)
            self.mt[i] = v

    def next(self):
        if self.index >= self.n:
            self.twist()
        y = self.mt[self.index]

        y = y ^ ((y >> self.u) and self.d)
        y = y ^ ((y << self.s) and self.b)
        y = y ^ ((y << self.t) and self.c)
        y = y ^ (y >> self.l)

        self.index += 1
        return y & ((1 << self.w) - 1)

    def twist(self):
        for i in range(0, self.n):
            x = (self.mt[i] & self.upper_mask) + (self.mt[(i+1) % self.n] & self.lower_mask)
            xa = x >> 1
            if (x & 1) != 0:
                xa = xa ^ self.a
            self.mt[i] = self.mt[(i + self.m) % self.n] ^ xa
        self.index = 0


