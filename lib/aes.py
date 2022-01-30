#!/usr/bin/env python3

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

def dec_cbc(ct, iv, aes):
    '''
    Implement CBC mode AES decryption on top of an ECB
    aes instance 'aes'. Decrypt 'ct' using iv 'iv'; 
    both byte objects.
    '''
    # blocks
    ct = [ct[i:i+16] for i in range(0, len(ct), 16)]
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
    pt = [pt[i:i+16] for i in range(0, len(pt), 16)]
    ct = b''
    for pblk in pt:
        pblk = bytes([x^y for x,y in zip(pblk, iv)])
        cblk = aes.encrypt(pblk)
        ct += cblk
        iv = cblk
    return ct
