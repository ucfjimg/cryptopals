#!/usr/bin/env python3

def xorb(a, b):
    '''
    xor the two byte objects 'a' and 'b' together. if 'a' and 'b'
    are of different lengths, the shorter object bounds the 
    length of the returned bytes.
    '''
    return bytes([x^y for x,y in zip(a,b)])

def xorenc(pt, key):
    '''
    Encrypt 'pt' (a bytes object) with the repeating key 'key'
    (also a bytes object)
    '''
    return bytes([x^key[i % len(key)] for i,x in enumerate(pt)])
