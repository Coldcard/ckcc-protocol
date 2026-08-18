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
doing the `encrypt_start()` (on the wire: `ncry`) command. You
must provide a public key, on the SECP256K curve, for Diffie-Hellman
key exchange in that command, plus an encryption version number
(`USB_NCRY_V1`, `V2` or `V3`). The device will provide its public
key (which is random and has no linkage to keys used for storing
funds). Both sides will do the usual EC point multiplication and
arrive at a shared session key.

## Version 1 (legacy, default)

Once the session key is established, it is used for AES-256-CTR
with a counter that starts at zero and increases for each byte sent
and received. Both directions share the same keystream.

Because requests and responses reuse one keystream, v1 does not
fully protect against passive eavesdroppers: an observer who knows
or can guess request plaintext (commands have predictable contents)
can recover the corresponding response plaintext by XORing the two
ciphertexts. Messages are also not authenticated, so tampering,
replay and reordering are not detected.

A new `ncry` command may be sent at any time to re-key.

## Version 2 (bound mode)

Version 2 keeps the v1 wire format, with the same cryptographic
limitations described above, but changes the rules of the session:

- after setup, all further commands must be encrypted, and
- a second `ncry` command is rejected until the next power cycle.

This prevents a malicious process from re-initializing the link
encryption mid-session, which is mostly a concern in HSM mode.

## Version 3 (authenticated)

Version 3 keeps the v2 bound-mode rules, but derives four independent
keys from the session key using HKDF-SHA256, bound to the label
`ccncry3`, the version number, and both ephemeral public keys: one
AES-CTR key and one HMAC key per direction. The key derivation is:

    transcript = SHA256("ccncry3" || LE32(version) || host_pubkey || device_pubkey)
    prk        = HMAC-SHA256(key=transcript, message=session_key)
    okm        = HKDF-Expand(prk, info="ccncry3", L=128)   # RFC 5869
    keys       = okm[0:32], okm[32:64], okm[64:96], okm[96:128]
               = h2d encrypt, h2d MAC, d2h encrypt, d2h MAC

Each encrypted message is:

    ciphertext = AES-256-CTR(plaintext)        # counter-0 stream, per direction
    tag        = HMAC-SHA256(key=mac_key, message=
                     direction || LE32(sequence) || LE32(len(ciphertext)) || ciphertext)[0:16]
    wire       = ciphertext || tag

where `direction` is `C2D\0` for requests and `D2C\0` for responses.
The 16-byte tag is verified before decryption. This gives each
direction an independent keystream, and provides message integrity,
rejection of same-session replay/reordering, and rejection of
cross-direction reflection. Any authentication, framing or transport
failure is terminal; reboot the Coldcard and reconnect. Sequence
numbers are unsigned 32-bit values and must never wrap.

V3 is opt-in and must be requested with the version field of `ncry`.
Firmware that does not support v3 rejects the request (`bad ncry
version`), and the client should close that attempt and may retry
with an older version explicitly.

## Endpoint Authentication

None of the above authenticates the Coldcard itself: the ECDH keys
are ephemeral and unsigned, so an active MiTM can still interpose
with a separate session on each side. If that's a concern for you,
you can do a `check_mitm()` command which returns a signature over
the session key using the Coldcard's main secret key used for funds.
Verify it against an xpub you already trust from a previous,
authenticated contact.

Part of the response to "start encryption" command is the extended
public key (XPUB) and master fingerprint that you will need for most
purposes anyway.

Code used for this session key setup and encryption is found in
`ckcc/client.py`. The EC and AES libraries to be used, may be changed
by overriding a few member functions.

# Details of Specific Commands

Please examine the CLI program (`ckcc/cli.py`) for examples of how
to sign transactions and similar.
