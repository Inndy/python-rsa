__all__ = [
    'pyversion',
    'egcd', 'modinv',
    'Str', 'Bytes', 'IntTypes',
    'bytes2int', 'int2bytes',
    'ensure_bytes', 'ensure_str',
    'profile',
    'enhex', 'unhex'
]

import binascii
import sys
import time

try: # python 2/3 compatability
    pyversion = 2
    Str, Bytes, IntTypes = unicode, str, (int, long) # unicode only in python2
    def bytes2int(b):
        return int(ensure_bytes(b)[::-1].encode('hex'), 16)
    def int2bytes(b, sz):
        return ('%x' % b).zfill(sz * 2).decode('hex')[::-1]
    if sys.version_info.minor < 7:
        print('python3.5+ or python2.7+ required')
        exit()
except:
    pyversion = 3
    Str, Bytes, IntTypes = str, bytes, (int,)
    def bytes2int(b):
        return int.from_bytes(ensure_bytes(b), 'little')
    def int2bytes(b, sz):
        return b.to_bytes(sz, 'little')
    if sys.version_info.minor < 5:
        print('python3.5+ or python2.7+ required')
        exit()

assert sys.version_info.major == pyversion

def ensure_bytes(s):
    if type(s) is Str:
        return s.encode('utf-8')
    elif type(s) in (Bytes, bytearray):
        return Bytes(s)
    else:
        raise TypeError

def ensure_str(s):
    if type(s) is Str:
        return s
    elif type(s) in (Bytes, bytearray):
        return Bytes(s).decode('utf-8')
    else:
        raise TypeError

def egcd(a, b):
    l, r = abs(a), abs(b)
    x, lx, y, ly = 0, 1, 1, 0
    while r:
        l, (q, r) = r, divmod(l, r)
        x, lx = lx - q*x, x
        y, ly = ly - q*y, y

    return l, -lx if a < 0 else lx, -ly if b < 0 else ly

def modinv(a, m):
    g, x, y = egcd(a, m) # solving g = a * x + m * y
    assert g == a * x + m * y
    if g != 1:
        raise ValueError
    return x % m

def profile(f, args=None):
    t = time.time()
    if not args:
        args = []
    r = f(*args)
    e = time.time()
    return e-t, r

def enhex(s):
    return binascii.hexlify(s)

def unhex(s):
    return binascii.unhexlify(s)

if __name__ == '__main__':
    print('[*] testing modinv')
    n = 32341
    for i in range(1, 12345):
        assert (i * modinv(i, n)) % n == 1
    print('[+] modinv test passed')
