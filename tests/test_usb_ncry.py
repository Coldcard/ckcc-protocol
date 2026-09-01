import pytest, pyaes
from hashlib import sha256
from hmac import HMAC
from struct import pack
from ckcc.constants import (
    AF_P2WPKH, USB_NCRY_V1, USB_NCRY_V2, USB_NCRY_V3,
    USB_V3_C2D, USB_V3_D2C, USB_V3_TAG_LEN,
)
from ckcc.client import ColdcardDevice, CCProtocolPacker, DEFAULT_TIMEOUT, usb_v3_keys
from ckcc.protocol import CCFramingError


def xor_bytes(left, right):
    assert len(left) == len(right)
    return bytes(a ^ b for a, b in zip(left, right))


# v2 tests require you to have firmware supporting usb encryption v2
# after each v2 test, coldcard needs to be reconnected


def test_ncry_v1():
    # USB_NCRY_V1 is the default
    dev = ColdcardDevice()
    session_key = dev.session_key
    assert session_key
    # re-establish shared secret
    dev.start_encryption()
    assert dev.ncry_ver == USB_NCRY_V1
    assert session_key != dev.session_key
    session_key = dev.session_key
    # we can do this many times over - it will always work
    dev.start_encryption()
    assert dev.ncry_ver == USB_NCRY_V1
    assert session_key != dev.session_key


def test_ncry_v2():
    # after this test, one needs to reconnect coldcard
    dev = ColdcardDevice(ncry_ver=USB_NCRY_V2)
    assert dev.session_key
    assert dev.ncry_ver == USB_NCRY_V2
    # cannot start new session - already bound
    with pytest.raises(Exception):
        dev.start_encryption()
    # cannot start new session even with v2 - already bound
    with pytest.raises(Exception):
        dev.start_encryption(version=USB_NCRY_V2)
    # if above conditions are met - all commands gonna be encrypted
    assert dev.ncry_ver == USB_NCRY_V2
    addr = dev.send_recv(CCProtocolPacker.show_address("m/84'/0'/0'/0/0", AF_P2WPKH), timeout=None)
    assert addr


def test_ncry_v2_via_start_encryption():
    dev = ColdcardDevice()
    assert dev.session_key
    assert dev.ncry_ver == USB_NCRY_V1
    dev.start_encryption(version=USB_NCRY_V2)
    assert dev.ncry_ver == USB_NCRY_V2
    # cannot start new session - already bound
    with pytest.raises(Exception):
        dev.start_encryption()
    # cannot start new session even with v2 - already bound
    with pytest.raises(Exception):
        dev.start_encryption(version=USB_NCRY_V2)
    # test some commands
    assert dev.ncry_ver == USB_NCRY_V2
    assert dev.encrypt_request is not None
    # if above conditions are met - all commands gonna be encrypted
    addr = dev.send_recv(CCProtocolPacker.show_address("m/84'/0'/0'/0/0", AF_P2WPKH), timeout=None)
    assert addr


def test_unsupported_version():
    dev = ColdcardDevice()
    with pytest.raises(ValueError):
        dev.start_encryption(version=0x4)
    dev.close()
    with pytest.raises(ValueError):
        ColdcardDevice(ncry_ver=0x4)


def test_ncry_v3_packer():
    pubkey = bytes(range(64))
    msg = CCProtocolPacker.encrypt_start(pubkey, version=USB_NCRY_V3)

    assert msg[:4] == b'ncry'
    assert msg[4:8] == pack('<I', USB_NCRY_V3)
    assert msg[8:] == pubkey


def test_ncry_v3_directional_keys_and_request_mac():
    session_key = sha256(b'ncry-v3-session').digest()
    host_pubkey = bytes(range(64))
    dev_pubkey = bytes(reversed(range(64)))

    dev = ColdcardDevice.__new__(ColdcardDevice)
    dev.aes_setup(session_key, version=USB_NCRY_V3,
                  host_pubkey=host_pubkey, device_pubkey=dev_pubkey)

    h2d_enc, h2d_mac, d2h_enc, d2h_mac = usb_v3_keys(
        session_key, host_pubkey, dev_pubkey)
    assert h2d_enc != d2h_enc
    assert h2d_mac != d2h_mac

    wire = dev.encrypt_request(b'pinghello')
    ciphertext, tag = wire[:-USB_V3_TAG_LEN], wire[-USB_V3_TAG_LEN:]
    expect_tag = HMAC(
        h2d_mac,
        pack('<4sII', USB_V3_C2D, 0, len(ciphertext)) + ciphertext,
        sha256
    ).digest()[:USB_V3_TAG_LEN]

    assert tag == expect_tag
    assert dev.tx_seq == 1


def test_ncry_v3_directional_streams_cannot_be_xored_to_decrypt():
    session_key = sha256(b'ncry-v3-stream-xor').digest()
    host_pubkey = bytes(range(64))
    dev_pubkey = bytes(reversed(range(64)))
    host_plaintext = b'host request plaintext'
    device_plaintext = b'device reply plaintext'

    h2d_enc, _, d2h_enc, _ = usb_v3_keys(session_key, host_pubkey, dev_pubkey)
    host_ciphertext = pyaes.AESModeOfOperationCTR(
        h2d_enc, pyaes.Counter(0)).encrypt(host_plaintext)
    device_ciphertext = pyaes.AESModeOfOperationCTR(
        d2h_enc, pyaes.Counter(0)).encrypt(device_plaintext)

    # With reused CTR keystreams, C1 xor C2 equals P1 xor P2, and knowing
    # one plaintext lets an observer recover the other. V3 direction keys
    # must break that relationship.
    assert xor_bytes(host_ciphertext, device_ciphertext) != xor_bytes(
        host_plaintext, device_plaintext)
    recovered_device_plaintext = xor_bytes(
        device_ciphertext, xor_bytes(host_ciphertext, host_plaintext))
    assert recovered_device_plaintext != device_plaintext


def test_ncry_v3_response_auth_and_replay_rejection():
    session_key = sha256(b'ncry-v3-response').digest()
    host_pubkey = bytes(range(64))
    dev_pubkey = bytes(reversed(range(64)))

    dev = ColdcardDevice.__new__(ColdcardDevice)
    dev.aes_setup(session_key, version=USB_NCRY_V3,
                  host_pubkey=host_pubkey, device_pubkey=dev_pubkey)

    _, _, d2h_enc, d2h_mac = usb_v3_keys(session_key, host_pubkey, dev_pubkey)
    plaintext = b'ascihello'
    ciphertext = pyaes.AESModeOfOperationCTR(
        d2h_enc, pyaes.Counter(0)).encrypt(plaintext)
    tag = HMAC(
        d2h_mac,
        pack('<4sII', USB_V3_D2C, 0, len(ciphertext)) + ciphertext,
        sha256
    ).digest()[:USB_V3_TAG_LEN]
    wire = ciphertext + tag

    assert dev.decrypt_response(wire) == plaintext
    assert dev.rx_seq == 1

    with pytest.raises(CCFramingError):
        dev.decrypt_response(wire)


def test_ncry_v3_response_tamper_rejected_before_sequence_increment():
    session_key = sha256(b'ncry-v3-tamper').digest()
    host_pubkey = bytes(range(64))
    dev_pubkey = bytes(reversed(range(64)))

    dev = ColdcardDevice.__new__(ColdcardDevice)
    dev.aes_setup(session_key, version=USB_NCRY_V3,
                  host_pubkey=host_pubkey, device_pubkey=dev_pubkey)

    _, _, d2h_enc, d2h_mac = usb_v3_keys(session_key, host_pubkey, dev_pubkey)
    plaintext = b'ascihello'
    ciphertext = pyaes.AESModeOfOperationCTR(
        d2h_enc, pyaes.Counter(0)).encrypt(plaintext)
    tag = HMAC(
        d2h_mac,
        pack('<4sII', USB_V3_D2C, 0, len(ciphertext)) + ciphertext,
        sha256
    ).digest()[:USB_V3_TAG_LEN]
    wire = bytearray(ciphertext + tag)
    wire[0] ^= 1

    with pytest.raises(CCFramingError):
        dev.decrypt_response(bytes(wire))
    assert dev.rx_seq == 0
    assert dev._v3_failed

    with pytest.raises(CCFramingError, match='session failed'):
        dev.decrypt_response(ciphertext + tag)


def test_ncry_v3_fixed_vectors():
    session_key = bytes(range(32))
    host_pubkey = bytes(range(64))
    dev_pubkey = bytes(range(64, 128))

    expect_keys = tuple(bytes.fromhex(v) for v in (
        '4ae5bbe99e5565f58383634c28916469c6f9777392c5fc4d16e1a4ccffce51d4',
        '8641e0d7e0e9d7610cd33bc6c6025dd772faaad259bb6492ea59362ab7e284df',
        '176e6002488acf16c63646f483d7965c78b41159863e77710fd069a3c7b4ab32',
        '07bdfcd21c34b50241509b146675a5f06d385242dbaf4d0060e2ccfee819706e',
    ))
    assert usb_v3_keys(session_key, host_pubkey, dev_pubkey) == expect_keys

    dev = ColdcardDevice.__new__(ColdcardDevice)
    dev.aes_setup(session_key, version=USB_NCRY_V3,
                  host_pubkey=host_pubkey, device_pubkey=dev_pubkey)

    request_plaintext = bytes.fromhex('70696e676e6372792d76332d766563746f72')
    request_wire = bytes.fromhex(
        '4d90a086a4411368708106e3b6ae321fef9d'
        '5fc1cfedaf2be32b1cdb55ce62b48029')
    assert dev.encrypt_request(request_plaintext) == request_wire

    response_plaintext = bytes.fromhex('62696e796e6372792d76332d766563746f72')
    response_wire = bytes.fromhex(
        '026d1b5205e4686f3682acab956ac2690efe'
        'f79887d299df4e655f887a112a7081d5')
    assert dev.decrypt_response(response_wire) == response_plaintext


def test_ncry_v3_sequence_exhaustion_is_terminal():
    session_key = sha256(b'ncry-v3-sequence-limit').digest()
    host_pubkey = bytes(range(64))
    dev_pubkey = bytes(reversed(range(64)))

    dev = ColdcardDevice.__new__(ColdcardDevice)
    dev.aes_setup(session_key, version=USB_NCRY_V3,
                  host_pubkey=host_pubkey, device_pubkey=dev_pubkey)
    dev.tx_seq = 0xffffffff

    dev.encrypt_request(b'pinglast-sequence')
    assert dev.tx_seq == 0x100000000

    with pytest.raises(CCFramingError, match='sequence exhausted'):
        dev.encrypt_request(b'pingone-too-many')
    assert dev._v3_failed


class FakeHID:
    # minimal stand-in for a hid.device / UnixSimulatorPipe
    def __init__(self, read_packets=(), write_ok=True):
        self.read_packets = list(read_packets)
        self.write_ok = write_ok
        self.written = []

    def write(self, buf):
        self.written.append(bytes(buf))
        return len(buf) if self.write_ok else -1

    def read(self, size, timeout_ms=None):
        if self.read_packets:
            return self.read_packets.pop(0)
        return b''        # nothing arrived: timeout


def make_v3_dev(fake_dev, **kw):
    session_key = kw.pop('session_key', sha256(b'ncry-v3-transport').digest())
    host_pubkey = bytes(range(64))
    dev_pubkey = bytes(reversed(range(64)))

    dev = ColdcardDevice.__new__(ColdcardDevice)
    dev.aes_setup(session_key, version=USB_NCRY_V3,
                  host_pubkey=host_pubkey, device_pubkey=dev_pubkey)
    dev.ncry_ver = USB_NCRY_V3
    dev.dev = fake_dev
    dev.timeout = DEFAULT_TIMEOUT
    return dev


def test_ncry_v3_read_timeout_is_terminal():
    dev = make_v3_dev(FakeHID())

    with pytest.raises(AssertionError, match='timeout reading USB EP'):
        dev.send_recv(CCProtocolPacker.ping(b'\x01' * 8), timeout=1)

    assert dev._v3_failed
    with pytest.raises(CCFramingError, match='session failed'):
        dev.send_recv(CCProtocolPacker.ping(b'\x02' * 8))


def test_ncry_v3_write_failure_is_terminal():
    dev = make_v3_dev(FakeHID(write_ok=False))

    with pytest.raises(AssertionError):
        dev.send_recv(CCProtocolPacker.ping(b'\x01' * 8))

    assert dev._v3_failed
    with pytest.raises(CCFramingError, match='session failed'):
        dev.send_recv(CCProtocolPacker.ping(b'\x02' * 8))


def test_ncry_v3_stale_response_not_misattributed_after_timeout():
    # regression test: a late, validly-tagged response from a timed-out
    # command must NOT be returned as the response to the next command
    session_key = sha256(b'ncry-v3-stale').digest()
    host_pubkey = bytes(range(64))
    dev_pubkey = bytes(reversed(range(64)))
    _, _, d2h_enc, d2h_mac = usb_v3_keys(session_key, host_pubkey, dev_pubkey)

    stale_plaintext = b'biny' + b'stale-result'
    ciphertext = pyaes.AESModeOfOperationCTR(
        d2h_enc, pyaes.Counter(0)).encrypt(stale_plaintext)
    tag = HMAC(
        d2h_mac,
        pack('<4sII', USB_V3_D2C, 0, len(ciphertext)) + ciphertext,
        sha256
    ).digest()[:USB_V3_TAG_LEN]
    wire = ciphertext + tag
    assert len(wire) <= 63
    queued = [bytes([0x80 | 0x40 | len(wire)]) + wire]

    dev = make_v3_dev(FakeHID(), session_key=session_key)

    # first command times out (its response arrives late, still queued)
    with pytest.raises(AssertionError, match='timeout reading USB EP'):
        dev.send_recv(CCProtocolPacker.ping(b'\x01' * 8), timeout=1)
    assert dev._v3_failed

    # now the stale response is queued; reused object must refuse to read it
    dev.dev.read_packets = queued
    with pytest.raises(CCFramingError, match='session failed'):
        dev.send_recv(CCProtocolPacker.ping(b'\x02' * 8))
    assert dev.dev.read_packets == queued, "stale response must stay unread"


def test_ncry_v3_overlong_response_rejected():
    # endless non-final HID fragments must not be buffered unboundedly
    frag = bytes([63]) + b'\x00' * 63        # 63 payload bytes, not last
    dev = make_v3_dev(FakeHID(read_packets=[frag] * 40))

    with pytest.raises(CCFramingError, match='Response too long'):
        dev.send_recv(CCProtocolPacker.ping(b'\x01' * 8))
    assert dev._v3_failed



def test_ncry_v3_app_error_response_does_not_poison_session():
    # an application-level error reply (b'err_') arrives as a complete,
    # validly-tagged response: both sides' streams stay synchronized, so
    # the session must NOT be poisoned (only transport/framing/auth
    # failures are terminal for v3)
    from ckcc.protocol import CCProtoError
    session_key = sha256(b'ncry-v3-app-err').digest()
    host_pubkey = bytes(range(64))
    dev_pubkey = bytes(reversed(range(64)))
    _, _, d2h_enc, d2h_mac = usb_v3_keys(session_key, host_pubkey, dev_pubkey)

    # one CTR object across both messages: stream continuity per direction
    ctr = pyaes.AESModeOfOperationCTR(d2h_enc, pyaes.Counter(0))

    def wrap(seq, plaintext):
        ct = ctr.encrypt(plaintext)
        tag = HMAC(d2h_mac, pack('<4sII', USB_V3_D2C, seq, len(ct)) + ct,
                   sha256).digest()[:USB_V3_TAG_LEN]
        wire = ct + tag
        assert len(wire) <= 63
        return bytes([0x80 | 0x40 | len(wire)]) + wire

    queued = [wrap(0, b'err_' + b'bogus command'), wrap(1, b'okay')]
    dev = make_v3_dev(FakeHID(read_packets=queued), session_key=session_key)

    with pytest.raises(CCProtoError, match='bogus command'):
        dev.send_recv(CCProtocolPacker.ping(b'\x01' * 8), expect_errors=True)
    assert not dev._v3_failed

    # session still usable: next command gets its own response (seq 1)
    assert dev.send_recv(CCProtocolPacker.ping(b'\x02' * 8)) is None
    assert not dev._v3_failed
