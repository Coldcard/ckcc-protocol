# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import re
import os
import copy
import json

from ckcc.utils import xfp2str
from ckcc.client import ColdcardDevice
from ckcc.protocol import CCProtocolPacker


MULTISIG_WALLET_TYPE_PATTERN = r"^\d+of\d+$"
MULTISIG_WALLET_KEY_PATTERN = r"^x\d+/$"


def is_hww_keystore(keystore: dict) -> bool:
    return keystore["type"] == "hardware"


def is_multisig_wallet(wallet: dict) -> bool:
    if re.match(MULTISIG_WALLET_TYPE_PATTERN, wallet["wallet_type"]):
        return True
    return False


def is_multisig_wallet_key(key: str) -> bool:
    if re.match(MULTISIG_WALLET_KEY_PATTERN, key):
        return True
    return False


def collect_multisig_hww_keystores_from_wallet(wallet: dict) -> dict:
    """Find all hardware keystore objects in multisig wallet dict"""
    if not is_multisig_wallet(wallet):
        raise RuntimeError("Not an electrum multisig wallet")
    return {
        key: value
        for key, value in wallet.items()
        if is_multisig_wallet_key(key)
        if is_hww_keystore(value)
    }


def multisig_find_target(keystores: dict, key: str, value: str) -> tuple:
    """Find target keystore in list of keystores by key equals value"""
    result = [
        (k, keystore)
        for k, keystore in keystores.items()
        if keystore.get(key, None) == value
    ]
    length = len(result)
    if length != 1:
        # if this is true, we have found more than one keystore and therefore
        # key value pair is ambiguous
        msg = "Found {} keystores.".format(length)
        raise RuntimeError(
            msg if length == 0 else msg + "{}:{} is ambiguous".format(key, value)
        )
    return result[0]


def filepath_append_cc(f_path: str) -> str:
    """Append '_cc' suffix to file path. Do consider one file extension"""
    dirname = os.path.dirname(f_path)
    filename, file_ext = os.path.splitext(os.path.basename(f_path))
    result = os.path.join(dirname, "{}_cc".format(filename) + file_ext)
    return result


def cc_adjust_hww_keystore(keystore: dict, dev: ColdcardDevice = None) -> dict:
    """Create new updated version of keystore"""
    new_keystore = copy.deepcopy(keystore)

    if not is_hww_keystore(keystore):
        raise RuntimeError("Not a hardware wallet type")

    # 1-3 can be done without coldcard connected
    #
    # 1. change hw type to coldcard
    new_keystore["hw_type"] = "coldcard"
    # 2. soft device id should be nullified
    new_keystore["soft_device_id"] = None
    # 3. remove cfg key if exists (ledger specific)
    if "cfg" in new_keystore:
        del new_keystore["cfg"]
    # 4. label ? we can do something about it - at least remove the label that is no longer in use
    new_keystore["label"] = "Coldcard {}".format(new_keystore["root_fingerprint"])

    # for next steps we need coldcard connected (unnecessary)
    if dev:
        # 4. label Coldcard + fingerprint
        xfp = dev.master_fingerprint
        xfp = xfp2str(xfp).lower()  # if any letters - lower them
        if xfp != new_keystore["root_fingerprint"]:
            raise RuntimeError(
                "Fingerprint missmatch! Is this a correct coldcard/wallet file?"
                " Make sure that your bip39 passphrase is in effect (if used)."
                " device fingerprint {};  wallet fingerprint {}".format(xfp, new_keystore["root_fingerprint"])
            )

        label = "Coldcard {}".format(xfp)
        new_keystore["label"] = label
        # 5. ckcc xpub (master xpub)
        master_ext_pubkey = dev.master_xpub
        new_keystore["ckcc_xpub"] = master_ext_pubkey
    return new_keystore


def cc_adjust_multisig_hww_keystore(wallet: dict, key: str, value: str, dev: ColdcardDevice = None) -> dict:
    """Update multisig wallet keystore"""
    # 1. find target keystore
    k, keystore = multisig_find_target(
        keystores=collect_multisig_hww_keystores_from_wallet(wallet),
        key=key,
        value=value,
    )
    # 2. create new adjusted keystore for target
    new_keystore = cc_adjust_hww_keystore(keystore, dev)
    # 3. update target keystore in wallet
    wallet[k] = new_keystore
    return wallet


def convert2cc(wallet_str: str, dev: ColdcardDevice = None, key: str = None, val: str = None):
    wallet = json.loads(wallet_str)
    wallet_type = wallet["wallet_type"]
    if wallet_type == "standard":
        new_keystore = cc_adjust_hww_keystore(wallet["keystore"], dev)
        wallet["keystore"] = new_keystore
    elif is_multisig_wallet(wallet):
        if key is None and val is None and dev is None:
            # dev is not defined, key val is not defined, we are in multisig - have to fail
            raise RuntimeError("--key and --val have to be specified for multisig wallets")
        elif key is None and val is None and dev:
            # user haven't provided arguments - try some auto-magic if coldcard is connected
            # look for root fingerprint
            cc_adjust_multisig_hww_keystore(
                wallet,
                key="root_fingerprint",
                value=xfp2str(dev.master_fingerprint).lower(),
                dev=dev
            )
            # is it sufficient to just check xfp?
            # shouldn't I try to re-create xpub (Vpub) or whatever I get as derivation path?
        else:
            # key val specified
            cc_adjust_multisig_hww_keystore(
                wallet,
                key=key,
                value=val,
                dev=dev
            )
    else:
        raise RuntimeError("Unsupported wallet type: {}".format(wallet_type))
    return json.dumps(wallet)
