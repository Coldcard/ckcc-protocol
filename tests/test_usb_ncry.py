import pytest
from ckcc.constants import AF_P2WPKH, USB_NCRY_V1, USB_NCRY_V2
from ckcc.client import ColdcardDevice, CCProtocolPacker


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
        dev.start_encryption(version=0x3)
    dev.close()
    with pytest.raises(ValueError):
        ColdcardDevice(ncry_ver=0x3)


