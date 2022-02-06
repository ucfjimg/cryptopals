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
            v = self.mt[i-1] >> (self.w-2)
            v = self.mt[i-1] ^ v
            v = self.f * v
            v += i
            v &= ((1 << self.w) - 1)
            self.mt[i] = v

    def next(self):
        if self.index >= self.n:
            self.twist()
        y = self.mt[self.index]

        # NB these are clamped to be 32-bit ops
        
        y = y ^ ((y >> self.u) & self.d)
        y &= 0xffffffff
        y = y ^ ((y << self.s) & self.b)
        y &= 0xffffffff
        y = y ^ ((y << self.t) & self.c)
        y &= 0xffffffff
        y = y ^ (y >> self.l)
        y &= 0xffffffff

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


def mt19937_untemper(y):
    def mask(bits):
        return (1 << bits) - 1

    def bit(v, idx):
        '''
        return the idx'th but of v, returning 0 
        for out of range index
        '''
        if idx < 0 or idx > 31:
            return 0
        return (v >> idx) & 1

    def solve_lshift(y, t, c):
        yn = 0
        for bn in range(0, 32):
            aa = bit(y, bn)
            bb = bit(yn, bn-t)
            cc = bit(c, bn)
            dd = aa ^ (bb & cc)
            yn |= (dd << bn)
        return yn

    # reverse y = y ^ (y >> self.l)
    top = y & (mask(18) << 14)
    bot = (y ^ (y >> 18)) & mask(14)
    y = top|bot

    # reverse y = y ^ ((y << self.t) & self.c)
    t = 15
    c = 0xefc60000
    y = solve_lshift(y, t, c)

    # reverse y = y ^ ((y << self.s) & self.b)
    s = 7
    b = 0x9D2C5680
    y = solve_lshift(y, s, b)

    # reverse y = y ^ ((y >> self.u) & self.d)
    # note that d is all 1's so we can ignore it
    yn = 0
    for bn in range(31, -1, -1):
        aa = bit(y, bn)
        bb = bit(yn, bn+11)
        yn |= ((aa ^ bb) << bn)

    return yn

def enc_mt(seed, data):
    seed &= 0xffff
    mt = mt19937(seed)
    ct = []
    for i in range(0, len(data), 4):
        by = min(4, len(data) - i)
        key = mt.next()
        for j in range(0, by):
            ct.append((key ^ data[i+j]) & 0xff)
            key >>= 8

    return bytes(ct)

def dec_mt(seed, data):
    return enc_mt(seed, data)
        
def modexp(a, b, n):
    '''
    compute a^b mod n
    '''
    e = 1
    while b != 0:
        if (b & 1) != 0:
            e = (e * a) % n
        a = (a * a) % n
        b = b >> 1

    return e

def gcd(a,b):
    '''
    Given two integers a and b, use Euclid's algorithm to find the 
    greatest common denominator
    '''
    while True:
        m = a % b
        if m == 0:
            return b
        a = b
        b = m

def egcd(a,b):
    '''
    Given two integers a and b, use Euclid's extended algorithm 
    to find the greatest common denominator and u,v such that
    ua + vb == gcd(a,b)
    '''
    history = []
    while True:
        r = a % b
        q = a // b
        if r == 0:
            break
        history.append(q)
        a = b
        b = r
    d = b
    history.reverse()

    u = 0
    v = 1
    for (q) in history:
        u, v = v, u - v * q

    return d,u,v

def invmod(a, m):
    '''
    Return the modular inverse of 'a', mod 'm'; that is, the solution
    to ax = 1 (mod m)
    '''
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception(f'{a} has no modular inverse mod {m}')
    return x % m

    
