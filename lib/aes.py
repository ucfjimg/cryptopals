#!/usr/bin/env python3

import struct

def split_blocks(b, blksize=16):
    '''
    Utility function to split a bytes object of crypt or plain
    text into a list of byte objects of the underlying block
    size.
    '''
    return [b[i:i+blksize] for i in range(0, len(b), blksize)]


def is_ecb(ct, blksize=16):
    '''
    Check the given cryptext to see if it is ECB mode. The check 
    makes the assumption that in a longer text, there will be
    repeated blocks.
    '''
    blocks = split_blocks(ct, blksize)
    blockset = set(blocks)
    return len(blocks) > len(blockset)

#
# pcks isn't AES specified but we always use it with AES
#
def pkcs7(data, blksize=16):
    '''
    Given a bytes object 'data', add padding bytes to it
    per PCKS#7 to make the length a multiple of 'blksize'
    '''
    pad = blksize - len(data) % blksize
    return data + bytes(pad * [pad])

def pkcs7_unpad(data, blksize):
    if len(data) == 0 or len(data) % blksize != 0:
        raise Exception('data is empty or not blocked aligned')
    padlen = data[-1]
    if padlen > blksize:
        raise Exception('invalid pad data')

    if data[-padlen:] != bytes(padlen * [padlen]):
        raise Exception('invalid pad data')

    return data[:-padlen]

def dec_cbc(ct, iv, aes):
    '''
    Implement CBC mode AES decryption on top of an ECB
    aes instance 'aes'. Decrypt 'ct' using iv 'iv'; 
    both byte objects.
    '''
    # blocks
    bs = aes.block_size
    ct = [ct[i:i+bs] for i in range(0, len(ct), bs)]
    pt = b''
    for cblk in ct:
        pblk = aes.decrypt(cblk)
        pblk = bytes([x^y for x,y in zip(pblk, iv)])
        iv = cblk 
        pt += pblk
    return pt

def enc_cbc(pt, iv, aes):
    '''
    Implement CBC mode AES encryption on top of an ECB
    aes instance 'aes'. Encrypt 'ct' using iv 'iv'; 
    both byte objects.
    '''
    # blocks
    bs = aes.block_size
    pt = [pt[i:i+bs] for i in range(0, len(pt), bs)]
    ct = b''
    for pblk in pt:
        pblk = bytes([x^y for x,y in zip(pblk, iv)])
        cblk = aes.encrypt(pblk)
        ct += cblk
        iv = cblk
    return ct

def dec_ctr(ct, nonce, aes):
    '''
    Encrypt using CTR mode AES. 'nonce' is a 64 bit integer nonce
    '''
    ctr = 0
    ct = split_blocks(ct, aes.block_size)
    pt = b''
    while len(ct) > 0:
        key = aes.encrypt(struct.pack('<QQ', nonce, ctr))
        ctr += 1
        pt += bytes([x^y for x,y in zip(ct[0], key)])
        ct = ct[1:]
    return pt

def enc_ctr(pt, nonce, aes):
    '''
    Decrypt using CTR mode AES. 'nonce' is a 64 bit integer nonce
    '''
    ctr = 0
    pt = split_blocks(pt, aes.block_size)
    ct = b''
    while len(pt) > 0:
        key = aes.encrypt(struct.pack('<QQ', nonce, ctr))
        ctr += 1
        ct += bytes([x^y for x,y in zip(pt[0], key)])
        pt = pt[1:]
    return ct

def edit_ctr(ct, nonce, offset, newpt, aes):
    '''
    Given a cryptext 'ct', the nonce 'nonce' and aes/key
    it was encrypted with, replace a section of the encrypted
    data at 'offset' with new plaintext 'newpt'

    'ct' and 'newpt' must be bytes. For simplicity this function
    cannot be used to extend 'ct'.
    '''
    
    if offset + len(newpt) > len(ct):
        raise Exception( "cannot use edit_ctr to append" )
    bs = aes.block_size
    blk0 = offset // bs
    blk1 = (offset + len(newpt) - 1) // bs
    
    blocks = split_blocks(ct, bs)
    blocks = [bytearray(x) for x in blocks]

    for blk in range(blk0, blk1+1):
        key = aes.encrypt(struct.pack('<QQ', nonce, blk))
        pt = bytearray([x^y for x,y in zip(blocks[blk], key)])
        start = offset % bs
        n = min(len(newpt), bs - start)
        pt[start:start+n] = newpt[:n]
        blocks[blk] = bytes([x^y for x,y in zip(pt, key)])
        offset += n
        newpt = newpt[n:]

    return b''.join(blocks)
            
def block_size(aes):
    '''
    Given an AES encryption function, determine the blocksize.
    Note that this can be ANY encryption-like function (i.e.
    it can be a wrapper that adds prefix or suffix bytes) as
    long as calling it with successive lengths of plaintext
    actually means that the plaintext passed to AES increments
    in the same manner. 'aes' must take a bytes object and
    return a bytes object.
    '''

    pt = b'A'
    l = len(aes(pt))
    while True:
        pt += b'A'
        m = len(aes(pt))
        if m > l:
            return m-l

