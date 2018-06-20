# USB Protocol of the Coldcard

The USB protocol is layered on top of a HID class interface. Send
us 64-byte "reports" (packets). We are a composite device that may
also support a ACM-style serial port or mass storage requests
depending on developer settings.

The first byte is for framing, and the remaining 63 bytes are the payload.

Up to about 2k of data can be sent in a sequence of 64-byte packets
this way. Only the last one can contain any size other than 63 bytes
of active data.

See `ckcc/client.py` for implementation.

Please note the Coldcard does not enable the USB port until after
a PIN code is sucessfully entered. Some USB commands will cause a
prompt on the device, which will require user interaction to approve
the action.

## Framing Byte

- always first byte
- can never be zero
- lower 6 bits are length of this packet (0..63)
- bit 0x80 is set if it's last packet in request/response
- bit 0x40 is set if packet is encrypted
- all illegal bit patterns are reserved for future
- all legal framed packets are 4 bytes or longer of payload

## Framed Packets

Packets going to the Coldcard start with a 4-byte command code
(text). Responses also have a 4-byte (text) header, but it describes
the signature of the data returned, and not what command it's
associated with.

## Requests / Responses

See `ckcc/protocol.py` for details:

`CCProtocolPacker()` for all commands you can send

`CCProtocolUnpacker.decode()` for all response types to expect.

# Link Level Encryption

At any time, the client may upgrade to encrypted communications by
doing the `encrypt_start()` (one the wire: `ncry`) command. You
must provide a public key, on the SECP256K curve, for Diffie-Hellman
key exchange in that command. The device will provide it's public
key (which is random and has no linkage to keys used for storing
funds). Both sides will do the usual EC point multiplication and
arrive at a shared session key.

Once the session key is established, it is used for AES-256-CTR
with a counter that starts at zero and increases for each byte sent
and received.

At this point, you can be sure that your communications are safe
from passive evesdroppers, but there is still a risk of active MiTM.
If that's a concern for you, you can do a `check_mitm()` command
which returns a signature over the session key using the Coldcard's
main secret key used for funds.

At this time we are not requiring encryption for all commands, but
that may change in the future. Since we do that, it's best to enable
encryption immediately and use it consistently. Part of the response
to "start encryption" command is the extended public key (XPUB) and
master fingerprint that you will need for most purposes anyway.

Code used for this session key setup and encryption is found in
`ckcc/client.py`. The EC and AES libraries to be used, may be changed
by overriding a few member functions.

# Details of Specific Commands

Please examine the CLI program (`ckcc/cli.py`) for examples of how
to sign transactions and similar.

