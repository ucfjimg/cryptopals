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
