#!/usr/bin/env python3

from os import path
from collections import defaultdict

_dir = path.split(__file__)[0]
_freq = path.join(_dir, 'freq.txt')


def _readfreq():
    lines = [x.rstrip() for x in open(_freq).readlines()]
    lines = [x.split(',') for x in lines]
    lines = [x for x in lines if len(x) == 2]
    lines = [(ord(x[0]), int(x[1])) for x in lines]
    return defaultdict(lambda: 0, lines)

_freq = _readfreq()

def _upper(x):
    if x >= ord('a') and x <= ord('z'):
        return x & ~0x20
    return x

def score(text):
    '''
    Score 'text' as English, using frequency analysis. As only
    single letter frequencies are considered, letter order 
    does not matter.
    '''
    text = [_upper(x) for x in text]
    return sum([_freq[x] for x in text])

