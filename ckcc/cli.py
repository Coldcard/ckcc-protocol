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
import hid, click, sys, os, pdb, struct, time, io
from pprint import pformat
from binascii import b2a_hex, a2b_hex
from hashlib import sha256
from base64 import b64encode
from functools import wraps

from ckcc.protocol import CCProtocolPacker, CCProtocolUnpacker
from ckcc.protocol import CCProtoError, CCUserRefused, CCBusyError
from ckcc.constants import MAX_MSG_LEN, MAX_BLK_LEN
from ckcc.constants import AF_P2WPKH, AF_CLASSIC, AF_P2WPKH_P2SH
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
def file_upload(filename, blksize):
    "Send file to Coldcard (PSBT transaction or firmware)"

    real_file_upload(filename, blksize)

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

@main.command('xfp')
@click.option('--swab', '-s', is_flag=True, help='Reverse endian of result (32-bit)')
def get_fingerprint(swab):
    "Get the fingerprint for this wallet (master level)"

    dev = ColdcardDevice(sn=force_serial)

    xfp = dev.master_fingerprint
    assert xfp

    if swab:
        xfp = struct.unpack("<I", struct.pack(">I", xfp))[0]

    click.echo('0x%08x' % xfp)

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
#@click.option('--just-txn', '-t', is_flag=True, help='Just the final transaction itself, nothing more')
@display_errors
def sign_transaction(psbt_in, psbt_out, verbose=False, hex_mode=False, finalize=True):
    "Approve a spending transaction (by signing it on Coldcard)"

    dev = ColdcardDevice(sn=force_serial)

    dev.check_mitm()

    # not enforcing policy here on msg contents, so we can define that on product
    taste = psbt_in.read(10)
    psbt_in.seek(0)
    if taste == b'70736274ff':
        # hex encoded; make binary
        psbt_in = io.BytesIO(a2b_hex(psbt_in.read()))
        hex_mode = True
    elif taste[0:5] != b'psbt\xff':
        click.echo("File doesn't have PSBT magic number at start.")
        sys.exit(1)

    # upload the transaction
    txn_len, sha = real_file_upload(psbt_in, dev=dev)

    # start the signing process
    ok = dev.send_recv(CCProtocolPacker.sign_transaction(txn_len, sha), timeout=None)
    assert ok == None

    result, _ = wait_and_download(dev, CCProtocolPacker.get_signed_txn(), 1)

    if finalize:
        # assume(?) transaction is completely signed, and output the
        # bitcoin transaction to be sent.
        # XXX maybe do this on embedded side, when txn is final?
        # XXX otherwise, need to parse PSBT and also handle combining properly
        pass

    # save it
    psbt_out.write(b2a_hex(result) if hex_mode else result)

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


# EOF
