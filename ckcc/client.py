#
# client.py
#
# Implement the desktop side of our Coldcard USB protocol.
#
# If you would like to use a different EC/AES library, you may subclass
# and override these member functions:
#
#   - ec_mult, ec_setup, aes_setup, check_mitm
#
import hid, sys, os
from binascii import b2a_hex, a2b_hex
from hashlib import sha256
from .protocol import CCProtocolPacker, CCProtocolUnpacker, CCProtoError, MAX_MSG_LEN, MAX_BLK_LEN

# unofficial, unpermissioned... USB numbers
COINKITE_VID = 0xd13e
CKCC_PID     = 0xcc10

class ColdcardDevice:
    def __init__(self, sn=None, dev=None, encrypt=True):

        if not dev and sn and '/' in sn:
            dev = UnixSimulatorPipe(sn)
            found = 'simulator'
            self.is_simulator = True

        if not dev:
            self.is_simulator = False

            for info in hid.enumerate(COINKITE_VID, CKCC_PID):
                found = info['serial_number']

                if sn and sn != found:
                    continue

                # only one interface per device, so only one 'path'
                dev = hid.device(serial=found)
                assert dev, "failed to open: "+found
                dev.open_path(info['path'])

                break

            if not dev:
                print("Could not find Coldcard!" 
                        if not sn else ('Cannot find CC with serial: '+sn))
                sys.exit(1)

        self.dev = dev
        self.serial = found

        # they will be defined after we've established a shared secret w/ device
        self.session_key = None
        self.encrypt_request = None
        self.decrypt_response = None
        self.master_xpub = None
        self.master_fingerprint = None

        self.resync()


        if encrypt:
            self.start_encryption()

    def resync(self):
        # flush anything already waiting on the EP
        while 1:
            junk = self.dev.read(64, timeout_ms=1)
            if not junk: break
            print("junk: %r" % junk)

        # write a special packet, that encodes data zero-length, and last
        rv = self.dev.write(b'\x80' + (b'\xff'*63))

        # shouldn't be needed:
        # flush anything already waiting on the EP
        while 1:
            junk = self.dev.read(64, timeout_ms=1)
            if not junk: break
            print("junk 2: %r" % junk)

        # check things
        assert self.dev.error() == ''
        assert self.dev.get_serial_number_string() == self.serial

    def send_recv(self, msg, expect_errors=False, verbose=0, timeout=1000, encrypt=True):
        # first byte of each 64-byte packet encodes length or packet-offset
        assert 4 <= len(msg) <= MAX_MSG_LEN, "msg length: %d" % len(msg)

        if encrypt:
            msg = self.encrypt_request(msg)

        left = len(msg)
        offset = 0
        while left > 0:
            here = min(63, left)

            buf = bytearray(64)
            buf[1:1+here] = msg[offset:offset+here]
            if here == left:
                # final one in sequence
                buf[0] = here | 0x80 | (0x40 if encrypt else 0x00)
            else:
                # more will be coming
                buf[0] = here

            assert len(buf) == 64, len(buf)

            if verbose:
                print("Tx [%2d]: %s (0x%x)" % (here, b2a_hex(buf), buf[0]))

            # test for issue #396 in hidapi <https://github.com/signal11/hidapi/issues/396>
            # but should no longer be possible w/ framing byte in [0] position
            assert buf[0] != b'\0'

            rv = self.dev.write(buf)
            assert rv == 64, repr(rv)

            offset += here
            left -= here

        # collect response, framed in the same manner
        resp = b''
        while 1:
            buf = self.dev.read(64, timeout_ms=(timeout or 0))

            assert buf, "timeout reading USB EP"

            # (trusting more than usual here)
            flag = buf[0]
            resp += bytes(buf[1:1+(flag & 0x3f)])
            if flag & 0x80:
                break

        if flag & 0x40:
            if verbose:
                print('Enc response: %s' % b2a_hex(resp))

            resp = self.decrypt_response(resp)

        try:
            if verbose:
                print("Rx [%2d]: %r" % (len(resp), b2a_hex(bytes(resp))))

            return CCProtocolUnpacker.decode(resp)
        except CCProtoError as e:
            if expect_errors: raise
            #print("Protocol error: %r" % e)
            raise
        except:
            print("Corrupt response: %r" % resp)
            raise

    def ec_setup(self):
        # Provides the ECSDA primatives in portable way.
        # Needed to do D-H session key aggreement and then AES.
        # - should be replaced in subclasses if you have other EC libraries
        # - curve is always secp256k1
        # - values are binary strings
        # - write whatever you want onto self.

        # - setup: return 65 of public key, and 16 bytes of AES IV
        # - second call: give the pubkey of far side, calculate the shared pt on curve
        from ecdsa.curves import SECP256k1
        from ecdsa import SigningKey

        self.my_key = SigningKey.generate(curve=SECP256k1, hashfunc=sha256)
        pubkey = self.my_key.get_verifying_key().to_string()
        assert len(pubkey) == 64

        #print("my pubkey = %s" % b2a_hex(pubkey))

        return pubkey

    def ec_mult(self, his_pubkey):
        # - second call: given the pubkey of far side, calculate the shared pt on curve
        # - creates session key based on that
        from ecdsa.curves import SECP256k1
        from ecdsa import VerifyingKey
        from ecdsa.util import number_to_string

        # Validate his pubkey a little: this call will check it's on the curve.
        assert len(his_pubkey) == 64
        his_pubkey = VerifyingKey.from_string(his_pubkey, curve=SECP256k1, hashfunc=sha256)

        #print("his pubkey = %s" % b2a_hex(his_pubkey.to_string()))

        # do the D-H thing
        pt = self.my_key.privkey.secret_multiplier * his_pubkey.pubkey.point

        # final key is sha256 of that point, serialized (64 bytes).
        order = SECP256k1.order
        kk = number_to_string(pt.x(), order) + number_to_string(pt.y(), order)

        del self.my_key

        return sha256(kk).digest()

    def aes_setup(self, session_key):
        # Load keys and define encrypt/decrypt functions
        # - for CTR mode, we have different counters in each direction, so need two instances
        # - count must start at zero, and increment in LSB for each block.
        import pyaes

        self.encrypt_request = pyaes.AESModeOfOperationCTR(session_key, pyaes.Counter(0)).decrypt
        self.decrypt_response = pyaes.AESModeOfOperationCTR(session_key, pyaes.Counter(0)).encrypt

    def mitm_verify(self, sig):
        assert ok, "MitM attack underway? Wrong pubkey used for session"

    def start_encryption(self):
        # setup encryption on the link
        # - pick our own key pair, IV for AES
        # - send IV and pubkey to device
        # - it replies with own pubkey
        # - determine what the session key was/is

        pubkey = self.ec_setup()

        msg = CCProtocolPacker.encrypt_start(pubkey)

        his_pubkey, fingerprint, xpub = self.send_recv(msg, encrypt=False)

        self.session_key = self.ec_mult(his_pubkey)

        # capture some public details of remote side's master key
        # - these can be empty/0x0 when no secrets on device yet
        self.master_xpub = str(xpub, 'ascii')
        self.master_fingerprint = fingerprint

        #print('sess key = %s' % b2a_hex(self.session_key))
        self.aes_setup(self.session_key)

    def check_mitm(self, sig=None):
        # Optional? verification against MiTM attack:
        # Using the master xpub, check a signature over the session public key, to
        # verify we talking directly to the real Coldcard (no active MitM between us).
        # - message is just the session key itself; no digests or prefixes
        # - no need for this unless concerned about *active* mitm on USB bus
        # - passive attackers (snoopers) will get nothing anyway, thanks to diffie-helman sauce
        # - unfortunately too slow to do everytime?

        assert self.master_xpub, "device doesn't have any secrets yet"
        assert self.session_key, "connection not yet in encrypted mode"

        try:
            from pycoin.key.BIP32Node import BIP32Node
            from pycoin.contrib.msg_signing import verify_message
            from pycoin.encoding  import from_bytes_32
            from base64 import b64encode
        except ImportError:
            raise RuntimeError("Missing pycoin for signature checking")

        # this request is delibrately slow on the device side
        if not sig:
            sig = self.send_recv(CCProtocolPacker.check_mitm(), timeout=5000)

        assert len(sig) == 65

        mk = BIP32Node.from_wallet_key(self.master_xpub)
        ok = verify_message(mk, b64encode(sig), msg_hash=from_bytes_32(self.session_key))

        if ok != True:
            raise RuntimeError("Possible MiTM attack: incorrect signatrue observed")


    def upload_file(self, data, verify=True, blksize=1024):
        # upload a single file, up to 1MB? in size. Can check arrives ok.
        chk = sha256(data).digest()

        for i in range(0, len(data), blksize):
            here = data[i:i+blksize]
            pos = self.send_recv(CCProtocolPacker.upload(i, len(data), here))
            assert pos == i

        if verify:
            rb = self.send_recv(CCProtocolPacker.sha256())
            assert rb == chk

        return len(data), chk

    def download_file(self, length, checksum, blksize=1024, file_number=1):
        # Download a single file, when you already know it's checksum. Will check arrives ok.
        data = b''
        chk = sha256()

        pos = 0
        while pos < length:
            here = self.send_recv(CCProtocolPacker.download(pos, min(blksize, length-pos), file_number))
            data += here
            chk.update(here)
            pos += len(here)
            assert len(here) > 0

        assert chk.digest() == checksum

        return data


class UnixSimulatorPipe:
    # Use a UNIX pipe to the simulator instead of a real USB connection.
    # - emulates the API of hidapi device object.

    def __init__(self, path):
        import socket, atexit
        self.pipe = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            self.pipe.connect(path)
        except FileNotFoundError:
            print("Cannot connect to simulator. Is it running?")
            sys.exit(1)

        pn = '/tmp/ckcc-client-%d.sock' % os.getpid()
        self.pipe.bind(pn)     # just needs any name
        atexit.register(os.unlink, pn)

    def read(self, max_count, timeout_ms=None):
        import socket
        if not timeout_ms:
            self.pipe.settimeout(None)
        else:
            self.pipe.settimeout(timeout_ms / 1000.0)

        try:
            return self.pipe.recv(max_count)
        except socket.timeout:
            return None

    def write(self, buf):
        assert len(buf) == 64
        self.pipe.settimeout(10)
        return self.pipe.send(buf)

    def error(self):
        return ''

    def get_serial_number_string(self):
        return 'simulator'

# EOF
