# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
from ckcc.utils import xfp2str
from ckcc.client import ColdcardDevice
from ckcc.protocol import CCProtocolPacker


def cc_adjust_hww_keystore(keystore: dict, dev: ColdcardDevice = None):
    """Modify electrum keystore dictionary in place"""
    assert keystore["type"] == "hardware", "Not a hardware wallet type"

    # 1-3 can be done without coldcard connected
    #
    # 1. change hw type to coldcard
    keystore["hw_type"] = "coldcard"
    # 2. soft device id should be nullified
    keystore["soft_device_id"] = None
    # 3. remove cfg key if exists (ledger specific)
    if "cfg" in keystore:
        del keystore["cfg"]
    # 4. label ? we can do something about it - at least remove the label that is no longer in use
    keystore["label"] = "Coldcard {}".format(keystore["root_fingerprint"])

    # for next steps we need coldcard connected (unnecessary)
    if dev:
        # 4. label Coldcard + fingerprint
        xfp = dev.master_fingerprint
        xfp = xfp2str(xfp).lower()  # if any letters - lower them
        if xfp != keystore["root_fingerprint"]:
            raise RuntimeError(
                "Fingerprint missmatch! Is this a correct coldcard/wallet file?"
                " Make sure that your bip39 passphrase is in effect (if used)."
                " device fingerprint {};  wallet fingerprint {}".format(xfp, keystore["root_fingerprint"])
            )

        label = "Coldcard {}".format(xfp)
        keystore["label"] = label
        # 5. ckcc xpub (master xpub)
        master_ext_pubkey = dev.send_recv(CCProtocolPacker.get_xpub("m"), timeout=None)
        keystore["ckcc_xpub"] = master_ext_pubkey