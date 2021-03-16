#!/usr/bin/env python
#
# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# To use this, install with:
#
#   pip install --editable .
#
# That will create the command "ckcc" in your path.
#
# Background:
# - see <https://github.com/trezor/cython-hidapi/blob/master/hid.pyx> for HID api 
#
#
import hid, click, sys, os, pdb, struct, time, io, re, json
from pprint import pformat
from binascii import b2a_hex, a2b_hex
from hashlib import sha256
from base64 import b64encode
from functools import wraps
from base64 import b64decode, b64encode

from ckcc.protocol import CCProtocolPacker, CCProtocolUnpacker
from ckcc.protocol import CCProtoError, CCUserRefused, CCBusyError
from ckcc.constants import MAX_MSG_LEN, MAX_BLK_LEN, MAX_USERNAME_LEN
from ckcc.constants import USER_AUTH_HMAC, USER_AUTH_TOTP, USER_AUTH_HOTP, USER_AUTH_SHOW_QR
from ckcc.constants import AF_CLASSIC, AF_P2SH, AF_P2WPKH, AF_P2WSH, AF_P2WPKH_P2SH, AF_P2WSH_P2SH
from ckcc.constants import STXN_FINALIZE, STXN_VISUALIZE, STXN_SIGNED
from ckcc.client import ColdcardDevice, COINKITE_VID, CKCC_PID
from ckcc.sigheader import FW_HEADER_SIZE, FW_HEADER_OFFSET, FW_HEADER_MAGIC
from ckcc.utils import dfu_parse, calc_local_pincode

global force_serial
force_serial = None
global force_plaintext
force_plaintext = False

# Cleanup display (supress traceback) for user-feedback exceptions
_sys_excepthook = sys.excepthook
def my_hook(ty, val, tb):
    if ty in { CCProtoError, CCUserRefused, CCBusyError }:
        print("\n\n%s" % val, file=sys.stderr)
    else:
        return _sys_excepthook(ty, val, tb)
sys.excepthook=my_hook

B2A = lambda x: b2a_hex(x).decode('ascii')

def xfp2str(xfp):
    # Standardized way to show an xpub's fingerprint... it's a 4-byte string
    # and not really an integer. Used to show as '0x%08x' but that's wrong endian.
    return b2a_hex(struct.pack('<I', xfp)).decode('ascii').upper()

def get_device():
    return ColdcardDevice(sn=force_serial, encrypt=not force_plaintext)

# Options we want for all commands
@click.group()
@click.option('--serial', '-s', default=None, metavar="HEX",
                    help="Operate on specific unit (default: first found)")
@click.option('--simulator', '-x', default=False, is_flag=True,
                    help="Connect to the simulator via Unix socket")
@click.option('--plaintext', '-P', default=False, is_flag=True,
                    help="Disable USB link-layer encryption")
def main(serial, simulator, plaintext):
    global force_serial, force_plaintext
    force_serial = serial
    force_plaintext = plaintext

    if simulator:
        force_serial = '/tmp/ckcc-simulator.sock'
    
def display_errors(f):
    # clean-up display of errors from Coldcard
    @wraps(f)
    def wrapper(*args, **kws):
        try:
            return f(*args, **kws)
        except CCProtoError as exc:
            click.echo("\n%s\n" % str(exc.args[0]))
            sys.exit(1)
    return wrapper
        
@main.command()
def debug():
    "Start interactive (local) debug session"
    import code
    import readline
    import atexit
    import os
            
    class HistoryConsole(code.InteractiveConsole):
        def __init__(self, locals=None, filename="<console>",
                     histfile=os.path.expanduser("~/.console-history")):
            code.InteractiveConsole.__init__(self, locals, filename)
            self.init_history(histfile)
        
        def init_history(self, histfile):
            readline.parse_and_bind("tab: complete")
            if hasattr(readline, "read_history_file"):
                try:
                    readline.read_history_file(histfile)
                except IOError:
                    pass
                atexit.register(self.save_history, histfile)
        
        def save_history(self, histfile):
            readline.write_history_file(histfile)

    # useful stuff
    import pdb
    from pdb import pm
    CC = ColdcardDevice(sn=force_serial, encrypt=False)
    SR = CC.send_recv

    cli = HistoryConsole(locals=dict(globals(), **locals()))
    cli.interact(banner="Go for it: 'CC' is the connected device, SR=CC.send_recv", exitmsg='')

@main.command('list')
def _list():
    "List all attached Coldcard devices"

    count = 0
    for info in hid.enumerate(COINKITE_VID, CKCC_PID):
        click.echo("\nColdcard {serial_number}:\n{nice}".format(
                            nice=pformat(info, indent=4)[1:-1], **info))
        count += 1

    if not count:
        click.echo("(none found)")

@main.command()
def logout():
    "Securely logout of device (will require replug to start over)"
    dev = get_device()

    resp = dev.send_recv(CCProtocolPacker.logout())
    print("Device says: %r" % resp if resp else "Okay!")

@main.command()
def reboot():
    "Reboot coldcard, force relogin and start over"
    dev = get_device()

    resp = dev.send_recv(CCProtocolPacker.reboot())
    print("Device says: %r" % resp if resp else "Okay!")

@main.command('bag')
@click.option('--number', '-n', metavar='BAG_NUMBER', default=None)
def bag_number(number):
    "Factory: set or read bag number -- single use only!"
    dev = get_device()

    nn = b'' if not number else number.encode('ascii')

    resp = dev.send_recv(CCProtocolPacker.bag_number(nn))

    print("Bag number: %r" % resp)

@main.command('test')
@click.option('--single', '-s', default=None,
            type=click.IntRange(0,255), help='If set, use this value on wire.')
def usb_test(single):
    "Test USB connection (debug/dev)"
    dev = get_device()

    rng = []
    rng.extend(range(55, 66))       # buggy lengths are around 64 
    rng.extend(range(1013, 1024))

    # we have 4 bytes of overhead (args) for ping cmd, so this will be max-length
    rng.extend(range(MAX_MSG_LEN-10, MAX_MSG_LEN-4))

    #print(repr(rng))

    for i in rng:
        print("Ping with length: %d" % i, end='')
        body = os.urandom(i) if single is None else bytes([single]*i)
        rb = dev.send_recv(CCProtocolPacker.ping(body))
        assert rb == body, "Fail @ len: %d, got back %d bytes\n%r !=\n%r" % (
                                        i, len(rb), b2a_hex(body), b2a_hex(rb))
        print("  Okay")


def real_file_upload(fd, blksize=MAX_BLK_LEN, do_upgrade=False, do_reboot=True, dev=None):
    dev = dev or get_device()

    # learn size (portable way)
    offset = 0
    sz = fd.seek(0, 2)
    fd.seek(0)

    if do_upgrade:
        # Unwrap DFU contents, if needed. Also handles raw binary file.
        try:
            if fd.read(5) == b'DfuSe':
                # expecting a DFU-wrapped file.
                fd.seek(0)
                offset, sz, *_ = dfu_parse(fd)
            else:
                # assume raw binary
                pass

            assert sz % 256 == 0, "un-aligned size: %s" % sz
            fd.seek(offset+FW_HEADER_OFFSET)
            hdr = fd.read(FW_HEADER_SIZE)

            magic = struct.unpack_from("<I", hdr)[0]
            #print("hdr @ 0x%x: %s" % (FW_HEADER_OFFSET, b2a_hex(hdr)))
        except Exception:
            magic = None

        if magic != FW_HEADER_MAGIC:
            click.echo("This does not look like a firmware file! Bad magic value.")
            sys.exit(1)

        fd.seek(offset)

    click.echo("%d bytes (start @ %d) to send from %r" % (sz, fd.tell(), 
            os.path.basename(fd.name) if hasattr(fd, 'name') else 'memory'), err=1)

    left = sz
    chk = sha256()
    with click.progressbar(range(0, sz, blksize), label="Uploading") as bar:
        for pos in bar:
            here = fd.read(min(blksize, left))
            if not here: break
            left -= len(here)
            result = dev.send_recv(CCProtocolPacker.upload(pos, sz, here))
            assert result == pos, "Got back: %r" % result
            chk.update(here)

    # do a verify
    expect = chk.digest()
    result = dev.send_recv(CCProtocolPacker.sha256())
    assert len(result) == 32
    if result != expect:
        click.echo("Wrong checksum:\nexpect: %s\n   got: %s" 
                    % (b2a_hex(expect).decode('ascii'), b2a_hex(result).decode('ascii')), err=1)
        sys.exit(1)

    if not do_upgrade:
        return sz, expect

    # AFTER fully uploaded and verified, write a copy of the signature header
    # onto the end of flash. Bootrom uses this to check entire file uploaded.
    result = dev.send_recv(CCProtocolPacker.upload(sz, sz+FW_HEADER_SIZE, hdr))
    assert result==sz, "failed to write trailer"

    # check also SHA after that!
    chk.update(hdr)
    expect = chk.digest()
    final_chk = dev.send_recv(CCProtocolPacker.sha256())
    assert expect == final_chk, "Checksum mismatch after all that?"

    if do_reboot:
        click.echo("Upgrade started. Observe Coldcard screen for progress.", err=1)
        dev.send_recv(CCProtocolPacker.reboot())

@main.command('upload')
@click.argument('filename', type=click.File('rb'))
@click.option('--blksize', default=MAX_BLK_LEN, 
            type=click.IntRange(256, MAX_BLK_LEN), help='Block size to use (testing)')
@click.option('--multisig', '-m', default=False, is_flag=True,
                                    help='Attempt multisig enroll using file')
def file_upload(filename, blksize, multisig=False):
    "Send file to Coldcard (PSBT transaction or firmware)"

    # NOTE: mostly for debug/dev usage.
    dev = get_device()

    file_len, sha = real_file_upload(filename, blksize, dev=dev)

    if multisig:
        dev.send_recv(CCProtocolPacker.multisig_enroll(file_len, sha))

@main.command('upgrade')
@click.argument('filename', type=click.File('rb'), metavar="FIRMWARE.dfu",
                    default='../stm32/firmware-signed.dfu')
@click.option('--stop-early', '-s', default=False, is_flag=True, help='Stop just before reboot')
def firmware_upgrade(filename, stop_early):
    "Send firmware file (.dfu) and trigger upgrade process"

    real_file_upload(filename, do_upgrade=True, do_reboot=(not stop_early))

# First account, not change, first index for Bitcoin mainnet in BIP44 path
BIP44_FIRST = "m/44'/0'/0'/0"

@main.command('xpub')
@click.argument('subpath', default='m')
def get_xpub(subpath):
    "Get the XPUB for this wallet (master level, or any derivation)"

    dev = get_device()

    if len(subpath) == 1:
        if subpath[0] == 'bip44':
            subpath = BIP44_FIRST

    xpub = dev.send_recv(CCProtocolPacker.get_xpub(subpath), timeout=None)

    click.echo(xpub)

@main.command('pubkey')
@click.argument('subpath', default='m')
def get_pubkey(subpath):
    '''Get the public key for a derivation path

    Dump 33-byte (compressed, SEC encoded) public key value.
    '''

    try:
        from pycoin.key.BIP32Node import BIP32Node
    except Exception:
        raise click.Abort("pycoin must be installed, not found.")

    dev = get_device()

    xpub = dev.send_recv(CCProtocolPacker.get_xpub(subpath), timeout=None)

    node = BIP32Node.from_hwif(xpub)

    click.echo(b2a_hex(node.sec()))

@main.command('xfp')
@click.option('--swab', '-s', is_flag=True, help='Reverse endian of result (32-bit)')
def get_fingerprint(swab):
    "Get the fingerprint for this wallet (master level)"

    dev = get_device()

    xfp = dev.master_fingerprint
    assert xfp

    if swab:
        # this is how we used to show XFP values: LE32 hex with 0x in front.
        click.echo('0x%08x' % xfp)
    else:
        # network order = BE32 = top 32-bits of hash160(pubkey) = 4 bytes in bip32 serialization
        click.echo(xfp2str(xfp))

@main.command('version')
def get_version():
    "Get the version of the firmware installed"

    dev = get_device()

    v = dev.send_recv(CCProtocolPacker.version())

    click.echo(v)

@main.command('chain')
def get_block_chain():
    '''Get which blockchain (Bitcoin/Testnet) is configured.

    BTC=>Bitcoin  or  XTN=>Bitcoin Testnet
    '''

    dev = get_device()

    code = dev.send_recv(CCProtocolPacker.block_chain())

    click.echo(code)


@main.command('eval')
@click.argument('stmt', nargs=-1)
def run_eval(stmt):
    "Simulator only: eval a python statement"
        
    dev = get_device()

    stmt = ' '.join(stmt)

    v = dev.send_recv(b'EVAL' + stmt.encode('utf-8'))

    click.echo(v)

@main.command('exec')
@click.argument('stmt', nargs=-1)
def run_eval(stmt):
    "Simulator only: exec a python script"
        
    dev = get_device()

    stmt = ' '.join(stmt)

    v = dev.send_recv(b'EXEC' + stmt.encode('utf-8'))

    click.echo(v)
    
@main.command('msg')
@click.argument('message')
@click.option('--path', '-p', default=BIP44_FIRST, help='Derivation for key to use')
@click.option('--verbose', '-v', is_flag=True, help='Include fancy ascii armour')
@click.option('--just-sig', '-j', is_flag=True, help='Just the signature itself, nothing more')
@click.option('--segwit', '-s', is_flag=True, help='Address in segwit native (p2wpkh, bech32)')
@click.option('--wrap', '-w', is_flag=True, help='Address in segwit wrapped in P2SH (p2wpkh)')
def sign_message(message, path, verbose=True, just_sig=False, wrap=False, segwit=False):
    "Sign a short text message"

    dev = get_device()

    if wrap:
        addr_fmt = AF_P2WPKH_P2SH
    elif segwit:
        addr_fmt = AF_P2WPKH
    else:
        addr_fmt = AF_CLASSIC

    # NOTE: initial version of firmware not expected to do segwit stuff right, since
    # standard very much still in flux, see: <https://github.com/bitcoin/bitcoin/issues/10542>

    # not enforcing policy here on msg contents, so we can define that on product
    message = message.encode('ascii') if not isinstance(message, bytes) else message

    ok = dev.send_recv(CCProtocolPacker.sign_message(message, path, addr_fmt), timeout=None)
    assert ok == None

    print("Waiting for OK on the Coldcard...", end='', file=sys.stderr)
    sys.stderr.flush()

    while 1:
        time.sleep(0.250)
        done = dev.send_recv(CCProtocolPacker.get_signed_msg(), timeout=None)
        if done == None:
            continue

        break

    print("\r                                  \r", end='', file=sys.stderr)
    sys.stderr.flush()

    if len(done) != 2:
        click.echo('Failed: %r' % done)
        sys.exit(1)

    addr, raw = done

    sig = str(b64encode(raw), 'ascii').replace('\n', '')

    if just_sig:
        click.echo(str(sig))
    elif verbose:
        click.echo('-----BEGIN SIGNED MESSAGE-----\n{msg}\n-----BEGIN '
                  'SIGNATURE-----\n{addr}\n{sig}\n-----END SIGNED MESSAGE-----'.format(
                        msg=message.decode('ascii'), addr=addr, sig=sig))
    else:
        click.echo('%s\n%s\n%s' % (message.decode('ascii'), addr, sig))
    
def wait_and_download(dev, req, fn):
    # Wait for user action on the device... by polling w/ indicated request
    # - also download resulting file

    print("Waiting for OK on the Coldcard...", end='', file=sys.stderr)
    sys.stderr.flush()

    while 1:
        time.sleep(0.250)
        done = dev.send_recv(req, timeout=None)
        if done == None:
            continue
        break

    print("\r                                  \r", end='', file=sys.stderr)
    sys.stderr.flush()

    if len(done) != 2:
        click.echo('Failed: %r' % done)
        sys.exit(1)

    result_len, result_sha = done

    # download the result.

    click.echo("Ok! Downloading result (%d bytes)" % result_len, err=1)
    result = dev.download_file(result_len, result_sha, file_number=fn)

    return result, result_sha
    
@main.command('sign')
@click.argument('psbt_in', type=click.File('rb'))
@click.argument('psbt_out', type=click.File('wb'), required=False)
@click.option('--verbose', '-v', is_flag=True, help='Show more details')
@click.option('--finalize', '-f', is_flag=True, help='Show final signed transaction, ready for transmission')
@click.option('--visualize', '-z', is_flag=True, help='Show text of Coldcard\'s interpretation of the transaction (does not create transaction, no interaction needed)')
@click.option('--signed', '-s', is_flag=True, help='Include a signature over visualization text')
@click.option('--hex', '-x', 'hex_mode', is_flag=True, help="Write out (signed) PSBT in hexidecimal")
@click.option('--base64', '-6', 'b64_mode', is_flag=True, help="Write out (signed) PSBT encoded in base64")
@display_errors
def sign_transaction(psbt_in, psbt_out=None, verbose=False, b64_mode=False, hex_mode=False, finalize=False, visualize=False, signed=False):
    "Approve a spending transaction by signing it on Coldcard"

    dev = get_device()
    dev.check_mitm()

    # Handle non-binary encodings, and incorrect files.
    taste = psbt_in.read(10)
    psbt_in.seek(0)
    if taste == b'70736274ff' or taste == b'70736274FF':
        # Looks hex encoded; make into binary again
        hx = ''.join(re.findall(r'[0-9a-fA-F]*', psbt_in.read().decode('ascii')))
        psbt_in = io.BytesIO(a2b_hex(hx))
    elif taste[0:6] == b'cHNidP':
        # Base64 encoded input
        psbt_in = io.BytesIO(b64decode(psbt_in.read()))
    elif taste[0:5] != b'psbt\xff':
        click.echo("File doesn't have PSBT magic number at start.")
        sys.exit(1)

    # upload the transaction
    txn_len, sha = real_file_upload(psbt_in, dev=dev)

    flags = 0x0
    if visualize or signed:
        flags |= STXN_VISUALIZE
        if signed:
            flags |= STXN_SIGNED
    elif finalize:
        flags |= STXN_FINALIZE

    # start the signing process
    ok = dev.send_recv(CCProtocolPacker.sign_transaction(txn_len, sha, flags=flags), timeout=None)
    assert ok == None

    # errors will raise here, no need for error display
    result, _ = wait_and_download(dev, CCProtocolPacker.get_signed_txn(), 1)

    # If 'finalize' is set, we are outputing a bitcoin transaction,
    # ready for the p2p network. If the CC wasn't able to finalize it,
    # an exception would have occured. Most people will want hex here, but
    # resisting the urge to force it.

    if visualize:
        if psbt_out:
            psbt_out.write(result)
        else:
            click.echo(result, nl=False)
    else:
        # save it
        if hex_mode:
            result = b2a_hex(result)
        elif b64_mode or (not psbt_out and os.isatty(0)):
            result = b64encode(result)

        if psbt_out:
            psbt_out.write(result)
        else:
            click.echo(result)

@main.command('backup')
@click.option('--outdir', '-d', 
            type=click.Path(exists=True,dir_okay=True, file_okay=False, writable=True),
            help="Save into indicated directory (auto filename)", default='.')
@click.option('--outfile', '-o', metavar="filename.7z",
                        help="Name for backup file", default=None,
                        type=click.File('wb'))
#@click.option('--verbose', '-v', is_flag=True, help='Show more details')
@display_errors
def start_backup(outdir, outfile, verbose=False):
    '''Creates 7z encrypted backup file after prompting user to remember a massive passphrase. \
Downloads the AES-encrypted data backup and by default, saves into current directory using \
a filename based on today's date.'''

    dev = get_device()

    dev.check_mitm()

    ok = dev.send_recv(CCProtocolPacker.start_backup())
    assert ok == None

    result, chk = wait_and_download(dev, CCProtocolPacker.get_backup_file(), 0)

    if outfile:
        outfile.write(result)
        outfile.close()
        fn = outfile.name
    else:
        assert outdir

        # pick a useful filename, if they gave a dirname
        fn = os.path.join(outdir, time.strftime('backup-%Y%m%d-%H%M.7z'))

        open(fn, 'wb').write(result)

    click.echo("Wrote %d bytes into: %s\nSHA256: %s" % (len(result), fn, str(b2a_hex(chk), 'ascii')))
        
@main.command('addr')
@click.argument('path', default=BIP44_FIRST, metavar='[m/1/2/3]', required=False)
@click.option('--segwit', '-s', is_flag=True, help='Show in segwit native (p2wpkh, bech32)')
@click.option('--wrap', '-w', is_flag=True, help='Show in segwit wrapped in P2SH (p2wpkh)')
@click.option('--quiet', '-q', is_flag=True, help='Show less details; just the address')
@click.option('--path', '-p', default=BIP44_FIRST, help='Derivation for key to show (or first arg)')
def show_address(path, quiet=False, segwit=False, wrap=False):
    "Show the human version of an address"

    dev = get_device()

    if wrap:
        addr_fmt = AF_P2WPKH_P2SH
    elif segwit:
        addr_fmt = AF_P2WPKH
    else:
        addr_fmt = AF_CLASSIC

    addr = dev.send_recv(CCProtocolPacker.show_address(path, addr_fmt), timeout=None)

    if quiet:
        click.echo(addr)
    else:
        click.echo('Displaying address:\n\n%s\n' % addr)

def str_to_int_path(xfp, path):
    # convert text  m/34'/33/44 into BIP174 binary compat format
    # - include hex for fingerprint (m) as first arg

    rv = [struct.unpack('<I', a2b_hex(xfp))[0]]
    for i in path.split('/'):
        if i == 'm': continue
        if not i: continue      # trailing or duplicated slashes
        
        if i[-1] in "'phHP":
            assert len(i) >= 2, i
            here = int(i[:-1]) | 0x80000000
        else:
            here = int(i)
            assert 0 <= here < 0x80000000, here
        
        rv.append(here)

    return rv


@main.command('p2sh')
@click.argument('script', type=str, nargs=1, required=True)
@click.argument('fingerprints', type=str, nargs=-1, required=True)
@click.option('--segwit', '-s', is_flag=True, help='Show in segwit native (p2wpkh, bech32)')
@click.option('--wrap', '-w', is_flag=True, help='Show as segwit wrapped in P2SH (p2wpkh)')
@click.option('--quiet', '-q', is_flag=True, help='Show less details; just the address')
def show_address(script, fingerprints, quiet=False, segwit=False, wrap=False):
    '''Show a multisig payment address on-screen.

    Needs a redeem script and list of fingerprint/path (4369050F/1/0/0 for example).

    This is provided as a demo or debug feature. You'll need need some way to
    generate the full redeem script (hex), and the fingerprints and paths used to
    generate each public key inside that. The order of fingerprint/paths must
    match order of pubkeys in the script.
    '''

    dev = get_device()

    addr_fmt = AF_P2SH
    if segwit:
        addr_fmt = AF_P2WSH
    if wrap:
        addr_fmt = AF_P2WSH_P2SH

    script = a2b_hex(script)
    N = len(fingerprints)

    assert 1 <= N <= 15, "bad N"

    min_signers = script[0] - 80
    assert 1 <= min_signers <= N, "bad M"

    assert script[-1] == 0xAE, "expect script to end with OP_CHECKMULTISIG"
    assert script[-2] == 80+N, "second last byte should encode N"

    xfp_paths = []
    for idx, xfp in enumerate(fingerprints):
        assert '/' in xfp, 'Needs a XFP/path: ' + xfp
        xfp, p = xfp.split('/', 1)

        xfp_paths.append(str_to_int_path(xfp, p))

    addr = dev.send_recv(CCProtocolPacker.show_p2sh_address(
                            min_signers, xfp_paths, script, addr_fmt=addr_fmt), timeout=None)

    if quiet:
        click.echo(addr)
    else:
        click.echo('Displaying address:\n\n%s\n' % addr)


@main.command('pass')
@click.argument('passphrase', required=False)
@click.option('--passphrase', prompt=True, hide_input=True,
              confirmation_prompt=False)
@click.option('--verbose', '-v', is_flag=True, help='Show new root xpub')
def bip39_passphrase(passphrase, verbose=False):
    "Provide a BIP39 passphrase"

    dev = get_device()

    dev.check_mitm()

    ok = dev.send_recv(CCProtocolPacker.bip39_passphrase(passphrase), timeout=None)
    assert ok == None

    print("Waiting for OK on the Coldcard...", end='', file=sys.stderr)
    sys.stderr.flush()

    while 1:
        time.sleep(0.250)
        done = dev.send_recv(CCProtocolPacker.get_passphrase_done(), timeout=None)
        if done == None:
            continue
        break

    print("\r                                  \r", end='', file=sys.stderr)
    sys.stderr.flush()

    if verbose:
        xpub = done
        click.echo(xpub)
    else:
        click.echo('Done.')


@main.command('multisig')
@click.option('--min-signers', '-m', type=int, help='Minimum M signers of N required to approve (default: all)', default=0)
@click.option('--signers', '-n', 'num_signers', type=int, help='N signers in wallet', default=3)
@click.option('--name', '-l', type=str, help='Wallet name on Coldcard', default='Unnamed')
@click.option('--output-file', '-f', type=click.File('wt', lazy=True),
                                help='Save configuration to file')
@click.option('--verbose', '-v', is_flag=True, help='Show file uploaded')
@click.option('--path', '-p', default="m/45'", help="Derivation for key (default: BIP45 = m/45')")
@click.option('--add', '-a', 'just_add', is_flag=True, help='Just show line required to add this Coldcard')
def enroll_xpub(name, min_signers, path,  num_signers, output_file=None, verbose=False, just_add=False):
    '''
Create a skeleton file which defines a multisig wallet.

When completed, use with: "ckcc upload -m wallet.txt" or put on SD card.
'''

    dev = get_device()
    dev.check_mitm()

    xfp = dev.master_fingerprint
    my_xpub = dev.send_recv(CCProtocolPacker.get_xpub(path), timeout=None)
    new_line = "%s: %s" % (xfp2str(xfp), my_xpub)

    if just_add:
        click.echo(new_line)
        sys.exit(0)

    N = num_signers

    if N < min_signers:
        N = min_signers

    if not (1 <= N < 15):
        click.echo("N must be 1..15")
        sys.exit(1)

    if min_signers == 0:
        min_signers = N 

    if not (1 <= min_signers <= N):
        click.echo(f"Minimum number of signers (M) must be between 1 and N={N}")
        sys.exit(1)

    if not (1 <= len(name) <= 20) or name != str(name.encode('utf8'), 'ascii', 'ignore'):
        click.echo("Name must be between 1 and 20 characters of ASCII.")
        sys.exit(1)

    # render into a template
    config = f'name: {name}\npolicy: {min_signers} of {N}\n\n#path: {path}\n{new_line}\n'
    if num_signers != 1:
        config += '\n'.join(f'#{i+2}# FINGERPRINT: xpub123123123123123' for i in range(num_signers-1))
        config += '\n'

    if verbose or not output_file:
        click.echo(config[:-1])

    if output_file:
        output_file.write(config)
        output_file.close()
        click.echo(f"Wrote to: {output_file.name}")

@main.command('hsm-start')
@click.argument('policy', type=click.Path(exists=True,dir_okay=False), metavar="policy.json", required=False)
@click.option('--dry-run', '-n', is_flag=True, help="Just validate file, don't upload")
def hsm_setup(policy=None, dry_run=False):
    '''
Enable Hardware Security Module (HSM) mode.

Upload policy file (or use existing policy) and start HSM mode on device. User must approve startup.
All PSBT's will be signed automatically based on that policy.

'''
    dev = get_device()
    dev.check_mitm()

    if policy:
        if dry_run:
            # check it looks reasonable, but jsut a JSON check
            raw = open(policy, 'rt').read()
            j = json.loads(raw)

            click.echo("Policy ok")
            sys.exit(0)

        file_len, sha = real_file_upload(open(policy, 'rb'), dev=dev)

        dev.send_recv(CCProtocolPacker.hsm_start(file_len, sha))
    else:
        if dry_run:
            raise click.UsageError("Dry run not useful without a policy file to check.")

        dev.send_recv(CCProtocolPacker.hsm_start())

    click.echo("Approve HSM policy on Coldcard screen.")

@main.command('hsm')
def hsm_status():
    '''
Get current status of HSM feature.

Is it running, what is the policy (summary only).
'''
    
    dev = get_device()
    dev.check_mitm()

    resp = dev.send_recv(CCProtocolPacker.hsm_status())

    o = json.loads(resp)

    click.echo(pformat(o))

@main.command('user')
@click.argument('username', type=str, metavar="USERNAME", required=True)
@click.option('--totp', '-t', 'totp_create', is_flag=True, help='Do TOTP and let Coldcard pick secret (default)')
@click.option('--pass', 'pick_pass', is_flag=True, help='Use a password picked by Coldcard')
@click.option('--ask-pass', '-a', is_flag=True, help='Define password here (interactive)')
@click.option('--totp-secret', '-s', help='BASE32 encoded secret for TOTP 2FA method (not great)')
@click.option('--text-secret', '-p', help='Provide password on command line (not great)')
@click.option('--delete', '-d', 'do_delete', is_flag=True, help='Remove a user by name')
@click.option('--show-qr', '-q', is_flag=True, help='Show enroll QR contents (locally)')
@click.option('--hotp', is_flag=True, help='Use HOTP instead of TOTP (dev only)')
def new_user(username, totp_create=False, totp_secret=None, text_secret=None, ask_pass=False,
                do_delete=False, debug=False, show_qr=False, hotp=False, pick_pass=False):
    '''
Create a new user on the Coldcard for HSM policy (also delete).

You can input a password (interactively), or one can be picked
by the Coldcard. When possible the QR to enrol your 2FA app will
be shown on the Coldcard screen.
'''
    from base64 import b32encode, b32decode

    username = username.encode('ascii')
    assert 1 <= len(username) <= MAX_USERNAME_LEN, "Username length wrong"

    dev = get_device()
    dev.check_mitm()

    if do_delete:
        dev.send_recv(CCProtocolPacker.delete_user(username))
        click.echo('Deleted, if it was there')
        return

    if ask_pass:
        assert not text_secret, "dont give and ask for password"
        text_secret = click.prompt('Password (hidden)', hide_input=True, confirmation_prompt=True)
        mode = USER_AUTH_HMAC

    if totp_secret:
        secret = b32decode(totp_secret, casefold=True)
        assert len(secret) in {10, 20}
        mode = USER_AUTH_TOTP
    elif hotp:
        mode = USER_AUTH_HOTP
        secret = b''
    elif pick_pass or text_secret:
        mode = USER_AUTH_HMAC
    else:
        # default is TOTP
        secret = b''
        mode = USER_AUTH_TOTP
    
    if mode == USER_AUTH_HMAC:
        # default is text passwords
        secret = dev.hash_password(text_secret.encode('utf8')) if text_secret else b''
        assert not show_qr, 'QR not appropriate for text passwords'

    if not secret and not show_qr:
        # ask the Coldcard to show the QR (for password or TOTP shared secret)
        mode |= USER_AUTH_SHOW_QR

    new_secret = dev.send_recv(CCProtocolPacker.create_user(username, mode, secret))

    if show_qr and new_secret:
        # format the URL thing ... needs a spec
        username = username.decode('ascii')
        secret = new_secret or b32encode(secret).decode('ascii')
        mode = 'hotp' if mode == USER_AUTH_HOTP else 'totp'
        click.echo(f'otpauth://{mode}/{username}?secret={secret}&issuer=Coldcard%20{dev.serial}')
    elif not text_secret and new_secret:
        click.echo(f'New password is: {new_secret}')
    else:
        click.echo('Done')

@main.command('local-conf')
@click.argument('psbt-file', type=click.File('rb'), required=True, metavar="Binary PSBT")
@click.option('--next', '-n', 'next_code', type=str, help='next_local_code from Coldcard (default: ask it)')
def user_auth(psbt_file, next_code=None):
    '''
Generate the 6-digit code needed for a specific PSBT file to authorize
it's signing on the Coldcard in HSM mode.
'''

    if not next_code:
        dev = get_device()
        dev.check_mitm()

        resp = dev.send_recv(CCProtocolPacker.hsm_status())
        o = json.loads(resp)

        assert o['active'], "Coldcard not in HSM mode"

        next_code = o['next_local_code']

    psbt_hash = sha256(psbt_file.read()).digest()

    rv = calc_local_pincode(psbt_hash, next_code)

    print("Local authorization code is:\n\n\t%s\n" % rv)

@main.command('auth')
@click.argument('username', type=str, metavar="USERNAME", required=True)
@click.argument('token', type=str, metavar="[TOTP]", required=False)
@click.option('--psbt-file', '-f', type=click.File('rb'), required=False)
@click.option('--password', '-p', is_flag=True, help="Prompt for password")
@click.option('--debug', '-d', is_flag=True, help='Show values used')
@click.option('--version3', '-3', is_flag=True, help='Support obsolete 3.x.x firmware')
def user_auth(username, token=None, password=None, prompt=None, totp=None, psbt_file=None, debug=False, version3=False):
    '''
Indicate specific user is present (for HSM).

Username and 2FA (TOTP, 6-digits) value or password are required. To use
password, the PSBT file in question must be provided.
'''
    import time
    from hmac import HMAC
    from hashlib import pbkdf2_hmac, sha256

    dryrun = True
    dev = get_device()
    dev.check_mitm()

    if psbt_file or password:
        if psbt_file:
            psbt_hash = sha256(psbt_file.read()).digest()
            dryrun = False
        else:
            psbt_hash = bytes(32)

        pw = token or click.prompt('Password (hidden)', hide_input=True)
        secret = dev.hash_password(pw.encode('utf8'), v3=version3)

        token = HMAC(secret, msg=psbt_hash, digestmod=sha256).digest()

        if debug:
            click.echo("  secret = %s" % B2A(secret))
            click.echo("    salt = %s" % B2A(salt))

        totp_time = 0
    else:
        if not token:
            token = click.prompt('2FA Token (6 digits)', hide_input=False)

        if len(token) != 6 or not token.isdigit():
            raise click.UsageError("2FA Token must be 6 decimal digits")

        token = token.encode('ascii')

        now = int(time.time())
        if now % 30 < 5:
            click.echo("NOTE: TOTP was on edge of expiry limit! Might not work.")
        totp_time =  now // 30

    #raise click.UsageError("Need PSBT file as part of HMAC for password")

    assert token and len(token) in {6, 32}
    username = username.encode('ascii')

    if debug:
        click.echo(" username = %s" % username.decode('ascii'))
        click.echo("    token = %s" % (B2A(token) if len(token) > 6 else token.decode('ascii')))
        click.echo("totp_time = %d" % totp_time)

    resp = dev.send_recv(CCProtocolPacker.user_auth(username, token, totp_time))

    if not resp:
        click.echo("Correct or queued")
    else:
        click.echo(f'Problem: {resp}')

@main.command('get-locker')
def get_storage_locker():
    "Get the value held in the Storage Locker (not Bitcoin related, reserved for HSM use)"

    dev = get_device()

    ls = dev.send_recv(CCProtocolPacker.get_storage_locker(), timeout=None)

    click.echo(ls)

# EOF
