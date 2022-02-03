#!/usr/bin/env python3

from crmath import modexp
from sha1 import Sha1Hash
import random

_p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
_g = 2

class DHKeys:
    '''
    A Diffie-Hellman public/private key pair
    ''' 
    def __init__(self):
        self._prv = random.randint(0, _p-1)
        self._pub = modexp(_g, self._prv, _p) 

    def public(self):
        '''
        The public key
        '''
        return self._pub

    def p(self):
        return _p

    def private(self):
        '''
        The private key
        '''
        return self._prv

class DHSession:
    '''
    A Diff-Hellman session with a shared symmetric key
    '''
    def __init__(self, keys, peer_pub):
        self._keys = keys
        self._peer_pub = peer_pub
        self._s = modexp(peer_pub, keys.private(), _p)

        s = self._s
        b = []
        while s != 0:
            b.append(s & 0xff)
            s >>= 8

        self._key = Sha1Hash().update(bytes(b)).digest()[:16]
        
    def s(self):
        return self._s
    
    def key(self):
        '''
        The shared symmetric key
        '''
        return self._key
