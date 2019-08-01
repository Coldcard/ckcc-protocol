#!/usr/bin/env python
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
import hid, click, sys, os, pdb, struct, time, io, re
from pprint import pformat
from binascii import b2a_hex, a2b_hex
from hashlib import sha256
from base64 import b64encode
from functools import wraps
from base64 import b64decode, b64encode

from ckcc.protocol import CCProtocolPacker, CCProtocolUnpacker
from ckcc.protocol import CCProtoError, CCUserRefused, CCBusyError
from ckcc.constants import MAX_MSG_LEN, MAX_BLK_LEN
from ckcc.constants import (
    AF_CLASSIC, AF_P2SH, AF_P2WPKH, AF_P2WSH, AF_P2WPKH_P2SH, AF_P2WSH_P2SH)
from ckcc.client import ColdcardDevice, COINKITE_VID, CKCC_PID
from ckcc.sigheader import FW_HEADER_SIZE, FW_HEADER_OFFSET, FW_HEADER_MAGIC
from ckcc.utils import dfu_parse

global force_serial
force_serial = None

# Cleanup display (supress traceback) for user-feedback exceptions
_sys_excepthook = sys.excepthook
def my_hook(ty, val, tb):
    if ty in { CCProtoError, CCUserRefused, CCBusyError }:
        print("\n\n%s" % val, file=sys.stderr)
    else:
        return _sys_excepthook(ty, val, tb)
sys.excepthook=my_hook

def xfp2str(xfp):
    # Standardized way to show an xpub's fingerprint... it's a 4-byte string
    # and not really an integer. Used to show as '0x%08x' but that's wrong endian.
    return b2a_hex(struct.pack('<I', xfp)).decode('ascii').upper()


# Options we want for all commands
@click.group()
@click.option('--serial', '-s', default=None, metavar="HEX",
                    help="Operate on specific unit (default: first found)")
@click.option('--simulator', '-x', default=False, is_flag=True,
                    help="Connect to the simulator via Unix socket")
def main(serial, simulator):
    global force_serial
    force_serial = serial

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
    dev = ColdcardDevice(sn=force_serial)

    resp = dev.send_recv(CCProtocolPacker.logout())
    print("Device says: %r" % resp if resp else "Okay!")

@main.command()
def reboot():
    "Reboot coldcard, force relogin and start over"
    dev = ColdcardDevice(sn=force_serial)

    resp = dev.send_recv(CCProtocolPacker.reboot())
    print("Device says: %r" % resp if resp else "Okay!")

@main.command('bag')
@click.option('--number', '-n', metavar='BAG_NUMBER', default=None)
def bag_number(number):
    "Factory: set or read bag number -- single use only!"
    dev = ColdcardDevice(sn=force_serial)

    nn = b'' if not number else number.encode('ascii')

    resp = dev.send_recv(CCProtocolPacker.bag_number(nn))

    print("Bag number: %r" % resp)

@main.command('test')
@click.option('--single', '-s', default=None,
            type=click.IntRange(0,255), help='If set, use this value on wire.')
def usb_test(single):
    "Test USB connection (debug/dev)"
    dev = ColdcardDevice(sn=force_serial)

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
    dev = dev or ColdcardDevice(sn=force_serial)

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
        except:
            magic = None

        if magic != FW_HEADER_MAGIC:
            click.echo("This does not look like a firmware file! Bad magic value.")
            sys.exit(1)

        fd.seek(offset)

    click.echo("%d bytes (start @ %d) to send from %r" % (sz, fd.tell(), 
            os.path.basename(fd.name) if hasattr(fd, 'name') else 'memory'))

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
        click.echo("Wrong checksum:\nexpect: %s\n   got: %s" % (b2a_hex(expect).decode('ascii'),
                                                              b2a_hex(result).decode('ascii')))
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
        click.echo("Upgrade started. Observe Coldcard screen for progress.")
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
    dev = ColdcardDevice(sn=force_serial)

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

    dev = ColdcardDevice(sn=force_serial)

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
    except:
        raise click.Abort("pycoin must be installed, not found.")

    dev = ColdcardDevice(sn=force_serial)

    xpub = dev.send_recv(CCProtocolPacker.get_xpub(subpath), timeout=None)

    node = BIP32Node.from_hwif(xpub)

    click.echo(b2a_hex(node.sec()))

@main.command('xfp')
@click.option('--swab', '-s', is_flag=True, help='Reverse endian of result (32-bit)')
def get_fingerprint(swab):
    "Get the fingerprint for this wallet (master level)"

    dev = ColdcardDevice(sn=force_serial)

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

    dev = ColdcardDevice(sn=force_serial)

    v = dev.send_recv(CCProtocolPacker.version())

    click.echo(v)

@main.command('eval')
@click.argument('stmt', nargs=-1)
def run_eval(stmt):
    "Simulator only: eval a python statement"
        
    dev = ColdcardDevice(sn=force_serial)

    stmt = ' '.join(stmt)

    v = dev.send_recv(b'EVAL' + stmt.encode('utf-8'))

    click.echo(v)

@main.command('exec')
@click.argument('stmt', nargs=-1)
def run_eval(stmt):
    "Simulator only: exec a python script"
        
    dev = ColdcardDevice(sn=force_serial)

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

    dev = ColdcardDevice(sn=force_serial)

    if wrap:
        addr_fmt = AF_P2WPKH_P2SH
    elif segwit:
        addr_fmt = AF_P2WPKH
    else:
        addr_fmt = AF_CLASSIC

    # NOTE: initial version of firmware not expected to do segwit stuff right, since
    # standard very much still in flux, see: <https://github.com/bitcoin/bitcoin/issues/10542>

    # not enforcing policy here on msg contents, so we can define that on product
    message = message.encode('ascii')

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

    click.echo("Ok! Downloading result (%d bytes)" % result_len)
    result = dev.download_file(result_len, result_sha, file_number=fn)

    return result, result_sha
    
@main.command('sign')
@click.argument('psbt_in', type=click.File('rb'))
@click.argument('psbt_out', type=click.File('wb'))
@click.option('--verbose', '-v', is_flag=True, help='Show more details')
@click.option('--finalize', '-f', is_flag=True, help='Show final signed transaction, ready for transmission')
@click.option('--hex', '-x', 'hex_mode', is_flag=True, help="Write out (signed) PSBT in hexidecimal")
@click.option('--base64', '-6', 'b64_mode', is_flag=True, help="Write out (signed) PSBT encoded in base64")
@display_errors
def sign_transaction(psbt_in, psbt_out, verbose=False, b64_mode=False, hex_mode=False, finalize=False):
    "Approve a spending transaction by signing it on Coldcard"

    # NOTE: not enforcing policy here on msg contents, so we can define that on product

    dev = ColdcardDevice(sn=force_serial)
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

    # start the signing process
    ok = dev.send_recv(CCProtocolPacker.sign_transaction(txn_len, sha, finalize=finalize), timeout=None)
    assert ok == None

    # errors will raise here, no need for error display
    result, _ = wait_and_download(dev, CCProtocolPacker.get_signed_txn(), 1)

    # If 'finalize' is set, we are outputing a bitcoin transaction,
    # ready for the p2p network. If the CC wasn't able to finalize it,
    # an exception would have occured. Most people will want hex here, but
    # resisting the urge to force it.

    # save it
    if hex_mode:
        result = b2a_hex(result)
    elif b64_mode:
        result = b64encode(result)

    psbt_out.write(result)

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

    dev = ColdcardDevice(sn=force_serial)

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
@click.option('--path', '-p', default=BIP44_FIRST, help='Derivation for key to show')
@click.option('--segwit', '-s', is_flag=True, help='Show in segwit native (p2wpkh, bech32)')
@click.option('--wrap', '-w', is_flag=True, help='Show in segwit wrapped in P2SH (p2wpkh)')
@click.option('--quiet', '-q', is_flag=True, help='Show less details; just the address')
def show_address(path, quiet=False, segwit=False, wrap=False):
    "Show the human version of an address"

    dev = ColdcardDevice(sn=force_serial)

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

    rv = [int(xfp, 16)]
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
@click.option('--min-signers', '-m', type=int, help='Minimum M signers of N required to approve (default: implied by script)', default=0)
@click.option('--path_prefix', '-p', default="m/45'", help='Common path derivation for all key to share (BIP45)')
@click.option('--segwit', '-s', is_flag=True, help='Show in segwit native (p2wpkh, bech32)')
@click.option('--wrap', '-w', is_flag=True, help='Show as segwit wrapped in P2SH (p2wpkh)')
@click.option('--quiet', '-q', is_flag=True, help='Show less details; just the address')
def show_address(path_prefix, script, fingerprints, min_signers=0, quiet=False, segwit=False, wrap=False):
    '''Show a multisig payment address on-screen

    Append subkey path to fingerprint value (4369050F/1/0/0 for example) or omit for 0/0/0

    This is provided as a demo or debug feature: you'll need the full redeem script (hex),
    and the fingerprints and paths used to generate each public key inside that.
    Order of fingerprint/path must match order of pubkeys in script.
    '''

    dev = ColdcardDevice(sn=force_serial)

    addr_fmt = AF_P2SH
    if segwit:
        addr_fmt = AF_P2WSH
    if wrap:
        addr_fmt = AF_P2WSH_P2SH

    script = a2b_hex(script)
    N = len(fingerprints)

    if N <= 16:
        if not min_signers:
            assert N <= 15
            min_signers = script[0] - 80
        else:
            assert min_signers == script[0], "M conficts with script"

        assert script[-1] == 0xAE, "expect script to end with OP_CHECKMULTISIG"
        assert script[-2] == 80+N, "second last byte should encode N"

    xfp_paths = []
    for idx, xfp in enumerate(fingerprints):
        if '/' not in xfp:
            # This isn't BIP45 compliant but we don't know the cosigner's index
            # values, since they would have been shuffled when the redeem script is sorted
            # Odds of this working, in general: near zero.
            p = path_prefix + '/0/0/0'
        else:
            # better if all paths provided
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

    dev = ColdcardDevice(sn=force_serial)

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
def enroll_xpub(name, min_signers, path,  num_signers, dry_run=False, output_file=None, verbose=False, just_add=False):
    '''
Create a skeleton file which defines a multisig wallet.

When completed, use with: "ckcc upload -m wallet.txt" or put on SD card.
'''

    dev = ColdcardDevice(sn=force_serial)
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

# EOF
