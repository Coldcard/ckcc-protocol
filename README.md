# Coldcard CLI and Python Interface Library

Coldcard is a Cheap, Ultra-secure & Opensource Hardware Wallet for #Bitcoin.

Get yours at [ColdcardWallet.com](http://coldcard.com)

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
  -s, --serial HEX  Operate on specific unit (default: first found)
  -x, --simulator   Connect to the simulator via Unix socket
  -P, --plaintext   Disable USB link-layer encryption
  --help            Show this message and exit.

Commands:
  addr        Show the human version of an address
  auth        Indicate specific user is present (for HSM).
  backup      Creates 7z encrypted backup file after...
  bag         Factory: set or read bag number -- single use...
  chain       Get which blockchain (Bitcoin/Testnet) is...
  convert2cc  Convert existing Electrum wallet file into...
  debug       Start interactive (local) debug session
  eval        Simulator only: eval a python statement
  exec        Simulator only: exec a python script
  get-locker  Get the value held in the Storage Locker (not...
  hsm         Get current status of HSM feature.
  hsm-start   Enable Hardware Security Module (HSM) mode.
  list        List all attached Coldcard devices
  local-conf  Generate the 6-digit code needed for a...
  logout      Securely logout of device (will require...
  msg         Sign a short text message
  multisig    Create a skeleton file which defines a...
  p2sh        Show a multisig payment address on-screen.
  pass        Provide a BIP39 passphrase
  pubkey      Get the public key for a derivation path Dump...
  reboot      Reboot coldcard, force relogin and start over
  sign        Approve a spending transaction by signing it...
  test        Test USB connection (debug/dev)
  upgrade     Send firmware file (.dfu) and trigger upgrade...
  upload      Send file to Coldcard (PSBT transaction or...
  user        Create a new user on the Coldcard for HSM...
  version     Get the version of the firmware installed
  xfp         Get the fingerprint for this wallet (master...
  xpub        Get the XPUB for this wallet (master level,...
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
  -v, --verbose    Show more details
  -f, --finalize   Show final signed transaction, ready for transmission
  -z, --visualize  Show text of Coldcard's interpretation of the transaction
                   (does not create transaction, no interaction needed)
  -s, --signed     Include a signature over visualization text
  -x, --hex        Write out (signed) PSBT in hexidecimal
  -6, --base64     Write out (signed) PSBT encoded in base64
  --help           Show this message and exit.

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


