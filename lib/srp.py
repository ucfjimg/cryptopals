#!/usr/bin/env python3

from crmath import modexp, mt19937
import time
import random

from Crypto.Hash import SHA256

# pre-agreed constants
#
N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3

def genpass(passwd):
    seed = int(time.time())
    salt = bytes(hex(mt19937(seed).next()), 'ascii')[2:]
    hash = SHA256.new()
    hash.update(salt + passwd)
    x = int(hash.hexdigest(), 16)
    v = modexp(g, x, N) 
    return salt.hex() + ':' + hex(v)[2:]

class AuthClient:
    def __init__(self, user, passwd):
        self.user = user
        self.passwd = bytes(passwd, 'ascii')
        
        # key pair
        self.a = random.randint(0, N-1)
        self.A = modexp(g, self.a, N)
    

    def run(self, s):
        msg = bytes(f'{self.user},{self.A}\n', 'ascii')
        s.send(msg) 
        line = self._recvline(s)
        salt,B = line.split(',')
        salt = bytes.fromhex(salt)
        B = int(B, 16)

        hash = SHA256.new()
        hash.update(bytes(hex(self.A) + hex(B), 'ascii'))
        u = int(hash.hexdigest(), 16)
        
        hash = SHA256.new()
        hash.update(salt + self.passwd)
        xH = hash.hexdigest()
        x = int(xH, 16)
        S = modexp(B - k * modexp(g, x, N), self.a + u * x, N)
        print('client S',S)
        hash = SHA256.new()
        hash.update(bytes(str(S), 'ascii'))
        K = hash.hexdigest()

        s.send(bytes(K + '\n', 'ascii'))

        line = self._recvline(s)
        print(line)


    def _recvline(self, s):
        line = b''
        while True:
            ch = s.recv(1)
            if ch == b'\n':
                break
            line += ch
        return line.decode('ascii')

class AuthServer:
    def __init__(self, userdb):
        self.userdb = userdb

    def run(self, s):
        line = self._recvline(s)
        user,A = line.split(',')
        A = int(A)
        user = self._finduser(user)
        if user == None:
            # really should continue exchange to not give 
            # away that user exists
            return
        salt,v = user[1:]
        v = int(v, 16)
        b = random.randint(0, N-1)
        B = k*v + modexp(g, b, N)
        msg = f'{salt},{hex(B)[2:]}\n'
        s.send(bytes(msg, 'ascii'))

        hash = SHA256.new()
        hash.update(bytes(hex(A) + hex(B), 'ascii'))
        u = int(hash.hexdigest(), 16)

        salt = int(salt, 16)
        
        Sp = modexp(A * modexp(v, u, N), b, N)
        hash = SHA256.new()
        hash.update(bytes(str(Sp), 'ascii'))
        K = hash.hexdigest()

        pk = self._recvline(s)

        if pk == K:
            s.send(b'200\n')
        else:
            s.send(b'403\n')


    def _recvline(self, s):
        line = b''
        while True:
            ch = s.recv(1)
            if ch == b'\n':
                break
            line += ch
        return line.decode('ascii')

    def _finduser(self, user):
        lines = open(self.userdb, 'r').readlines()
        lines = [x.strip().split(':') for x in lines]
        for l in lines:
            if l[0] == user:
                return l
        return None


        

