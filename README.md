# Coldcard CLI and Python Interface Library

Coldcard is an affordable, ultra-secure and open-source hardware
wallet for Bitcoin. Built for hardcore Bitcoin users who demand
maximum security.

Learn more and get yours at: [Coldcard.com](http://coldcard.com)

This is the python code and command-line utilities you need to communicate with it over USB.

## Setup For Everyday Use

- `pip install 'ckcc-protocol[cli]'`

This installs a single helpful command line program: `ckcc`

If you just want the python library, use:

- `pip install ckcc-protocol`


## Setup If You Might Change the Code

- do a git checkout
- probably make a fresh virtual env
- run:

```
pip install -r requirements.txt
pip install --editable '.[cli]'
```

## Requirements

- python 3.6 or higher
- `hidapi` for USB HID access in a portable way.
- see `requirements.txt` file for more details.


# CLI Examples

## Command Arguments

```
% ckcc
Usage: ckcc [OPTIONS] COMMAND [ARGS]...

Options:
  -s, --serial HEX                Operate on specific unit (default: first
                                  found)
  -c, --socket ckcc-simulator-<pid>.sock
                                  Operate on specific simulator
  -x, --simulator                 Connect to the simulator via Unix socket
  -P, --plaintext                 Disable USB link-layer encryption
  --help                          Show this message and exit.

Commands:
  addr        Show the human version of an address
  auth        Indicate specific user is present (for HSM).
  backup      Creates 7z encrypted backup file after prompting user to...
  bag         Factory: set or read bag number -- single use only!
  chain       Get which blockchain (Bitcoin/Testnet) is configured.
  convert2cc  Convert existing Electrum wallet file into COLDCARD wallet...
  debug       Start interactive (local) debug session
  eval        Simulator only: eval a python statement
  exec        Simulator only: exec a python script
  get-locker  Get the value held in the Storage Locker (not Bitcoin...
  hsm         Get current status of HSM feature.
  hsm-start   Enable Hardware Security Module (HSM) mode.
  list        List all attached Coldcard devices
  local-conf  Generate the 6-digit code needed for a specific PSBT file...
  logout      Securely logout of device (will require replug to start over)
  miniscript  Miniscript related commands
  msg         Sign a short text message
  multisig    Create a skeleton file which defines a multisig wallet.
  p2sh        Show a multisig payment address on-screen.
  pass        Provide a BIP39 passphrase
  pubkey      Get the public key for a derivation path
  reboot      Reboot coldcard, force relogin and start over
  restore     Uploads 7z encrypted backup file & starts backup restore...
  sign        Approve a spending transaction by signing it on Coldcard
  test        Test USB connection (debug/dev)
  upgrade     Send firmware file (.dfu) and trigger upgrade process
  upload      Send file to Coldcard (PSBT transaction or firmware)
  user        Create a new user on the Coldcard for HSM policy (also...
  version     Get the version of the firmware installed
  xfp         Get the fingerprint for this wallet (master level)
  xpub        Get the XPUB for this wallet (master level, or any derivation)
```


## Message Signing

```
% ckcc msg --help
Usage: ckcc msg [OPTIONS] MESSAGE

  Sign a short text message

Options:
  -p, --path DERIVATION  Derivation for key to use [default: m/44'/0'/0'/0/0]
  -v, --verbose          Include fancy ascii armour
  -j, --just-sig         Just the signature itself, nothing more
  -s, --segwit           Address in segwit native (p2wpkh, bech32)
  -w, --wrap             Address in segwit wrapped in P2SH (p2wpkh)
  --help                 Show this message and exit.

% ckcc msg "Hello Coldcard" -p m/34/23/33
Waiting for OK on the Coldcard...
Hello Coldcard                    
1KSXaNHh3G4sfTMsp9q8CmACeqsJn46drd
H4mTuwMUdnu3MyMA+6aJ3hiAF4L0WBDZFseTEno511hNN8/THIeM4GW4SnrcJJhS3WxMZEWFdEIZDSP+H5aIcao=
```


## Transaction Signing

```
% ckcc sign --help
Usage: ckcc sign [OPTIONS] PSBT_IN [PSBT_OUT]

  Approve a spending transaction by signing it on Coldcard

Options:
  -f, --finalize    Show final signed transaction, ready for transmission
  -z, --visualize   Show text of Coldcard's interpretation of the transaction
                    (does not create transaction, no interaction needed)
  -p, --pushtx URL  Broadcast transaction via provided PushTx URL. Shortcut
                    options: coldcard, mempool
  -s, --signed      Include a signature over visualization text
  -x, --hex         Write out (signed) PSBT in hexidecimal
  -6, --base64      Write out (signed) PSBT encoded in base64
  --help            Show this message and exit.

% (... acquire PSBT file for what you want to do ...)

% ckcc sign example.psbt out.psbt
5071 bytes (start @ 0) to send from 'example.psbt'
Uploading  [####################################]  100%
Waiting for OK on the Coldcard...
Ok! Downloading result (5119 bytes)

%  hexdump -C out.psbt | head -3
00000000  70 73 62 74 ff 01 00 fd  22 04 02 00 00 00 04 3f  |psbt...."......?|
00000010  ee 16 30 9d 14 82 36 dd  c8 3e 9e 4f 94 47 83 00  |..0...6..>.O.G..|
00000020  c2 23 e1 06 22 1b 02 0e  bd c8 1c 71 79 7d 3c 02  |.#.."......qy}<.|
00000030  00 00 00 00 fe ff ff ff  4c 85 a0 2c 80 cb 2c 01  |........L..,..,.|

```

## Miniscript

```
% ckcc miniscript --help
Usage: ckcc miniscript [OPTIONS] COMMAND [ARGS]...

  Miniscript related commands

Options:
  --help  Show this message and exit.

Commands:
  addr    Get miniscript internal/external chain address by index with on...
  del     Delete registered miniscript wallet by name with on device...
  enroll  Enroll miniscript wallet
  get     Get registered miniscript wallet by name.
  ls      List registered miniscript wallet names.
```

## Backup/Restore

```
% ckcc backup --help
Usage: ckcc backup [OPTIONS]

  Creates 7z encrypted backup file after prompting user to remember a massive
  passphrase. Downloads the AES-encrypted data backup and by default, saves
  into current directory using a filename based on today's date.

Options:
  -d, --outdir DIRECTORY     Save into indicated directory (auto filename)
  -o, --outfile filename.7z  Name for backup file
  --help                     Show this message and exit.
```

```
% ckcc restore --help
Usage: ckcc restore [OPTIONS] backup.7z

  Uploads 7z encrypted backup file & starts backup restore process. User needs
  to specify what kind of backup is being uploaded. Default is 7z encrypted
  file with word-based password. Use -p/--password flag if your backup has
  custom not word-based password. User is prompted to enter backup password on
  the device.

Options:
  -c, --plaintext  Force plaintext restore. No need to use if file has proper
                   '.txt' suffix
  -p, --password   This backup has custom password. Not words.
  -t, --tmp        Force restoring backup as temporary seed. Only works for
                   seedless Coldcard.
  --help           Show this message and exit.
```
