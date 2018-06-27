import struct
from collections import namedtuple

def dfu_parse(fd):
    # do just a little parsing of DFU headers, to find start/length of main binary
    # - not trying to support anything but what ../stm32/Makefile will generate
    # - see external/micropython/tools/pydfu.py for details
    # - works sequentially only
    fd.seek(0)

    def consume(xfd, tname, fmt, names):
        # Parses the struct defined by `fmt` from `data`, stores the parsed fields
        # into a named tuple using `names`. Returns the named tuple.
        size = struct.calcsize(fmt)
        here = xfd.read(size)
        ty = namedtuple(tname, names.split())
        values = struct.unpack(fmt, here)
        return ty(*values)

    dfu_prefix = consume(fd, 'DFU', '<5sBIB', 'signature version size targets')

    #print('dfu: ' + repr(dfu_prefix))

    assert dfu_prefix.signature == b'DfuSe', "Not a DFU file (bad magic)"

    for idx in range(dfu_prefix.targets):

        prefix = consume(fd, 'Target', '<6sBI255s2I', 
                                   'signature altsetting named name size elements')

        #print("target%d: %r" % (idx, prefix))

        for ei in range(prefix.elements):
            # Decode target prefix
            #   <   little endian
            #   I   uint32_t    element address
            #   I   uint32_t    element size
            elem = consume(fd, 'Element', '<2I', 'addr size')

            #print("target%d: %r" % (ei, elem))

            # assume bootloader at least 32k, and targeting flash.
            assert elem.addr >= 0x8008000, "Bad address?"

            yield fd.tell()
            yield elem.size

# EOF
