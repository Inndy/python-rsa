import itertools
import logging
import math
import os
import random
import sys
import timeit
import utils

logger = logging.getLogger('prime')

KNOWN_PRIME = [2, 3, 5, 7, 11]

SEED, GENERATOR, RMAX, STATE = 0x28d2c378a13f7985f, 0x2404894e07c9c9fb72524198122d966b81584bcf517f9ac3bca80b1e3b4991e11, 0x2f2191d53fd937c2716bb869cfac40240e3042f21d6ca1cf9f09498a496fe7983, None
def randinit():
    global STATE
    STATE = ((SEED * GENERATOR) ^ 0x245c7bfcc07aff5df56a6c354c6b527e92daf65b06bfb34e1e50e2c1444a48943) % RMAX

def _randrange(a, b):
    global STATE
    if STATE == None:
        randinit()
    r = b - a
    s = 0
    while s < r:
        STATE = ((STATE * GENERATOR) ^ SEED) % RMAX
        s = (s * 103 + STATE) ^ s >> 3
    return b + s % r

if os.getenv('NONRANDOM', False):
    print('[*] Non-random mode enabled')
    randrange = _randrange
else:
    randrange = random.randrange

def binsearch(x, arr):
    l, r = 0, len(arr) - 1

    while l <= r:
        m = (l + r) >> 1
        v = arr[m]
        if v < x:
            l = m + 1
        elif v > x:
            r = m - 1
        else:
            return True

    return False

def prime_generator():
    for p in KNOWN_PRIME:
        yield p
    n = KNOWN_PRIME[-1] - KNOWN_PRIME[-1] % 6

    def test(x):
        if x <= KNOWN_PRIME[-1]:
            return binsearch(x, KNOWN_PRIME)

        for p in KNOWN_PRIME:
            if x % p == 0:
                return False

        KNOWN_PRIME.append(x)
        return True

    while True:
        if test(n - 1):
            yield n - 1
        if test(n + 1):
            yield n + 1
        n += 6

PRIMES_3000 = list(itertools.takewhile(lambda x: x < 3000, prime_generator()))

def length_in_bits(x):
    return int(math.log(x, 2))

def is_prime(x):
    x = int(x)
    if x < 1:
        raise ValueError('value too small')
    if x < 3000:
        return binsearch(x, PRIMES_3000)
    if x % 2 == 0:
        return False

    stop = int(x ** 0.5)
    for p in prime_generator():
        if p > stop:
            return True
        if x % p == 0:
            return False

def is_probable_prime(x, check=12, recheck=0):
    if x < 3000:
        return is_prime(x)
    if x % 2 == 0:
        return False

    if not check or check < 5:
        check = max(int(math.log(math.log(x), 2) * 1.5), 5)

    def _try_comp(a, d, n, s):
        b = pow(a, d, n)
        if b == 1:
            return False
        n_1 = n - 1
        for i in range(s):
            if b == n_1:
                return False
            b = pow(b, 2, n) # b = (b * b) % n
        return True

    d = x - 1
    s = 0
    while d & 1 == 0:
        d, s = d >> 1, s + 1

    if any(_try_comp(p, d, x, s) for p in PRIMES_3000[:check]):
        return False
    if recheck < 1:
        return True
    return not any(_try_comp(p, d, x, s) for p in random.sample(PRIMES_3000[check:], recheck))

def randprime_range(a, b, c=None):
    if not c:
        if b > 2**64:
            c = int(math.log(math.log(b, 10), 2) * 1.5)
        else:
            c = 13

    while True:
        k = randrange(a, b) | 1 # ensure it's not even
        if is_probable_prime(k, c):
            return k

def randprime_bits(n=256):
    return randprime_range(2**n, 2**(n+1))

if __name__ == '__main__':
    for bits in (16, 32, 64, 128, 256, 512, 1024):
        res = None
        def p(s):
            global res
            res = s
        t = timeit.timeit(lambda: p(randprime_bits(bits)), number=1)
        print('%4d bits / %g secs / prime = %x' % (bits, t, res))
