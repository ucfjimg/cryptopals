#!/usr/bin/env python3

from Crypto.Util import number
from crmath import gcd, invmod, modexp

def genkey(bits):
    '''
    Returns a random key pair (public, private)
    '''
    e = 3
    t = e

    # we need primes that make a totient that lets us
    # get the inverse of e, mod the totient
    while gcd(e, t) != 1:
        p = number.getPrime(bits)
        q = number.getPrime(bits)
        n = p*q
        t = (p-1) * (q-1)
    d = invmod(e, t)
    return ((n,e), (n,d))


def enc(m, pub):
    '''
    Encrypt a message with an RSA public key
    '''
    n, e = pub
    return modexp(m, e, n)
    
def dec(c, priv):
    '''
    Decrpypt a message with an ESA private key
    '''
    n, d = priv
    return modexp(c, d, n)

