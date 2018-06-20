# Coldcard CLI and Python Interface Library

Coldcard is a Cheap, Ultra-secure & Opensource Hardware Wallet
for #Bitcoin and other crypto-currencies. 

Get yours at [ColdcardWallet.com](http://coldcardwallet.com)

This is the python code, and command-line utilities you need to communciate with it over USB.

## Setup For Everyday Use

- `pip install ckcc-protocol`

## More Advanced Setup For Everyday Use

- do a git checkout
- run `python setup.py install`

## Setup If You Might Change the Code


- do a git checkout
- run `pip install --editable .`


## Requirements

- python3.6 or higher
- `hidapi` for USB HID access in a portable way.
- see `requirements.txt` file for more details.
