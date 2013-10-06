from electrum.bitcoin import *
from electrum.util import user_dir
from binascii import unhexlify, hexlify
import os

def header_from_string(s):
    hex_to_int = lambda s: int('0x' + s[::-1].encode('hex'), 16)
    h = {}
    h['version'] = hex_to_int(s[0:4])
    h['prev_block_hash'] = hash_encode(s[4:36])
    h['merkle_root'] = hash_encode(s[36:68])
    h['timestamp'] = hex_to_int(s[68:72])
    h['bits'] = hex_to_int(s[72:76])
    h['nonce'] = hex_to_int(s[76:80])
    return h

def header_to_string(res):
    s = int_to_hex(res.get('version'),4) \
        + rev_hex(res.get('prev_block_hash')) \
        + rev_hex(res.get('merkle_root')) \
        + int_to_hex(int(res.get('timestamp')),4) \
        + int_to_hex(int(res.get('bits')),4) \
        + int_to_hex(int(res.get('nonce')),4)
    return s


def hash_valid(bits, H):
    H = map(ord, H)
    b = bits & 0xffffff
    e = (bits >> 24) & 0xff    
    
    if e >= 3:
        e -= 3
    else:
        b >>= (3-e)<<3
        e = 0
    
    downto = lambda j,k: xrange(j,k-1,-1)
    
    for i in downto(31, e+4):
        if H[i] != 0:
            return False
    l = 3
    for i in downto(e+3, e+0):
        bb = (b >> (l<<3)) & 0xff
        l -= 1
        if H[i] < bb:
            return True
        elif H[i] > bb:
            return False
    for i in downto(e-1, 0):
        if H[i] != 0:
            return False
    return True


def header_valid(hdr):
    hdrhash = Hash(hdr)
    hdrinfo = header_from_string(hdr)
    bits = hdrinfo['bits']
    return hash_valid(bits, hdrhash)

assert(header_valid(unhexlify('0200000062e3e9827da93bbed6918191c1c1d80fca683fb1f9e202283e00000000000000010b1f9b8e7babc9e61fd25181ed19c99ea3f345dad236667d3fdfc6e928cca8108e0b523287541928e5eac8')))
assert(hash_valid(0x1b0404cb, unhexlify('00000000000404CB000000000000000000000000000000000000000000000000')[::-1]))
assert(hash_valid(0x1d00ffff, unhexlify('00000000FFFF0000000000000000000000000000000000000000000000000000')[::-1]))

f = open(os.path.join(user_dir(), 'blockchain_headers'), 'rb')
while True:
    hdr = f.read(80)
    if hdr == '':
        break
    assert(header_valid(hdr))
