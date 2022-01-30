#!/usr/bin/env python3

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
