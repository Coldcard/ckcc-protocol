# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#

import binascii, hashlib, struct, hmac, base64
from collections import namedtuple
from typing import Optional

from ckcc.constants import AF_P2WSH, AF_P2WSH_P2SH, AF_P2SH
from ckcc.constants import AF_P2WPKH, AF_P2TR, AF_CLASSIC, AF_P2WPKH_P2SH


B2A = lambda x: binascii.b2a_hex(x).decode('ascii')


def xfp2str(xfp):
    # Standardized way to show an xpub's fingerprint... it's a 4-byte string
    # and not really an integer. Used to show as '0x%08x' but that's wrong endian.
    return binascii.b2a_hex(struct.pack('<I', xfp)).decode('ascii').upper()

def dfu_parse(fd):
    # do just a little parsing of DFU headers, to find start/length of main binary
    # - not trying to support anything but what ../stm32/Makefile will generate
    # - see external/micropython/tools/pydfu.py for details
    # - works sequentially only
    fd.seek(0)

    def consume(xfd, tname, fmt, names):
        # Parses the struct defined by `fmt` from `data`, stores the parsed fields
        # into a named tuple using `names`. Returns the named tuple.
        size = struct.calcsize(fmt)
        here = xfd.read(size)
        ty = namedtuple(tname, names.split())
        values = struct.unpack(fmt, here)
        return ty(*values)

    dfu_prefix = consume(fd, 'DFU', '<5sBIB', 'signature version size targets')

    #print('dfu: ' + repr(dfu_prefix))

    assert dfu_prefix.signature == b'DfuSe', "Not a DFU file (bad magic)"

    for _ in range(dfu_prefix.targets):

        prefix = consume(fd, 'Target', '<6sBI255s2I', 
                                   'signature altsetting named name size elements')

        #print("target%d: %r" % (idx, prefix))

        for _ in range(prefix.elements):
            # Decode target prefix
            #   <   little endian
            #   I   uint32_t    element address
            #   I   uint32_t    element size
            elem = consume(fd, 'Element', '<2I', 'addr size')

            #print("target%d: %r" % (ei, elem))

            # assume bootloader at least 32k, and targeting flash.
            assert elem.addr >= 0x8008000, "Bad address?"

            yield fd.tell()
            yield elem.size

# Adapted from https://github.com/petertodd/python-bitcoinlib/blob/master/bitcoin/base58.py
def decode_xpub(s):
    assert s[1:].startswith('pub')
    b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    # Convert the string to an integer
    n = 0
    for c in s:
        n *= 58
        if c not in b58_digits:
            raise ValueError('Character %r is not a valid base58 character' % c)
        digit = b58_digits.index(c)
        n += digit

    # Convert the integer to bytes
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = binascii.unhexlify(h.encode('utf8'))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == b58_digits[0]: pad += 1
        else: break
    decoded = b'\x00' * pad + res

    # Get the pubkey and chaincode
    return decoded[-37:-4], decoded[-69:-37]

def get_pubkey_string(b):
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

    x = int.from_bytes(b[1:], byteorder="big")
    y = pow((x*x*x + 7) % p, (p + 1) // 4, p)
    if (y & 1 != b[0] & 1):
        y = p - y
    return x.to_bytes(32, byteorder="big") + y.to_bytes(32, byteorder="big")


def calc_local_pincode(psbt_sha, next_local_code):
    # In HSM mode, you will need this function to generate
    # the next 6-digit code for the local user.
    #
    # - next_local_code comes from the hsm_status response
    # - psbt_sha is sha256() over the binary PSBT you will be submitting
    #
    key = binascii.a2b_base64(next_local_code)
    assert len(key) >= 15
    assert len(psbt_sha) == 32
    digest = hmac.new(key, psbt_sha, hashlib.sha256).digest()

    num = struct.unpack('>I', digest[-4:])[0] & 0x7fffffff

    return '%06d' % (num % 1000000)


def descriptor_template(xfp: str, xpub: str, path: str, fmt: int, m: int = None) -> Optional[str]:
    if m is None:
        m = "M"
    key_exp = "[%s%s]%s/0/*" % (xfp.lower(), path.replace("m", ''), xpub)
    if fmt == AF_P2SH:
        descriptor_template = "sh(sortedmulti(%s,%s,...))"
    elif fmt == AF_P2WSH_P2SH:
        descriptor_template = "sh(wsh(sortedmulti(%s,%s,...)))"
    elif fmt == AF_P2WSH:
        descriptor_template = "wsh(sortedmulti(%s,%s,...))"
    else:
        return None
    res = descriptor_template % (m, key_exp)
    return res


def addr_fmt_help(dev, wrap=False, segwit=False, taproot=False):
    chain = 0
    if dev.master_xpub and dev.master_xpub[0] == "t":
        # testnet
        chain = 1
    if wrap:
        addr_fmt = AF_P2WPKH_P2SH
        af_path = f"m/49h/{chain}h/0h/0/0"
    elif segwit:
        addr_fmt = AF_P2WPKH
        af_path = f"m/84h/{chain}h/0h/0/0"
    elif taproot:
        addr_fmt = AF_P2TR
        af_path = f"m/86h/{chain}h/0h/0/0"
    else:
        addr_fmt = AF_CLASSIC
        af_path = f"m/44h/{chain}h/0h/0/0"

    return addr_fmt, af_path


def b2a_base64url(s):
    # see <https://datatracker.ietf.org/doc/html/rfc4648#section-5>
    # '=' still needs to be removed https://docs.python.org/3/library/base64.html#base64.urlsafe_b64encode
    return base64.urlsafe_b64encode(s).rstrip(b'=\n').decode()


def txn_to_pushtx_url(txn, base_url, sha=None, chain="BTC", verify_sha=False):
    assert ("http://" in base_url) or ("https://" in base_url), "url schema"
    assert base_url[-1] in "#?&", "Final char must be # or ? or &."
    url = base_url
    url += 't=' + b2a_base64url(txn)

    if sha is None:
        sha = hashlib.sha256(txn).digest()
    elif verify_sha:
        assert sha == hashlib.sha256(txn).digest(), "wrong hash"

    url += '&c=' + b2a_base64url(sha[-8:])

    if chain != 'BTC':
        url += '&n=' + chain  # XTN or XRT
    return url

# EOF
