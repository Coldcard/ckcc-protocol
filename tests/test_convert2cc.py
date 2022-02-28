import os
import re
import json
import pytest
from click.testing import CliRunner

from ckcc.cli import electrum_convert2cc
from ckcc.electrum import (
    filepath_append_cc, multisig_find_target, collect_multisig_hww_keystores_from_wallet,
    cc_adjust_hww_keystore, is_multisig_wallet_key, is_multisig_wallet
)


# expecting cwd to be ckcc-protocol
test_data_path = os.path.join("tests", "test_data")
encrypted_path = os.path.join(test_data_path, "encrypted")
ledger_path = os.path.join(test_data_path, "ledger")
trezor_path = os.path.join(test_data_path, "trezor.json")
bip32_path = os.path.join(test_data_path, "bip32_wallet")
a2fa_path = os.path.join(test_data_path, "2fa_wallet")
import_path = os.path.join(test_data_path, "import_wallet")
multi3of5_path = os.path.join(test_data_path, "multi3of5")


def assert_keystore(keystore):
    assert keystore["hw_type"] == "coldcard"
    assert "cfg" not in keystore
    assert keystore["label"] == "Coldcard {}".format(keystore["root_fingerprint"])
    assert keystore["soft_device_id"] is None
    # as this is run without coldcard connected - no ckcc_xpub
    # assert "ckcc_xpub" not in keystore


def test_multisig_find_target():
    for pth in [ledger_path, trezor_path, bip32_path, a2fa_path]:
        with open(pth, "r") as f:
            wallet = json.loads(f.read())
        with pytest.raises(RuntimeError):
            multisig_find_target(
                keystores=collect_multisig_hww_keystores_from_wallet(wallet),
                key="hw_type",  # key and value does not matter here as exc is raised before they can be used
                value="ledger"
            )

    with open(multi3of5_path, "r") as f:
        wallet = json.loads(f.read())
    keystores = collect_multisig_hww_keystores_from_wallet(wallet)
    assert len(keystores) == 2  # only two are hardware
    for hw_type in ["trezor", "ledger"]:
        key, keystore = multisig_find_target(
            keystores=keystores,
            key="hw_type",
            value=hw_type
        )
        assert wallet[key] == keystore
        new_keystore = cc_adjust_hww_keystore(keystore)
        assert_keystore(new_keystore)


def test_filepath_append_cc():
    assert filepath_append_cc("ledger_wallet") == "ledger_wallet_cc"
    assert filepath_append_cc("ledger_wallet.json") == "ledger_wallet_cc.json"
    assert filepath_append_cc("ledger wallet.json") == "ledger wallet_cc.json"
    assert filepath_append_cc("/ledger_wallet") == "/ledger_wallet_cc"
    assert filepath_append_cc("/tmp/.../ledger_wallet") == "/tmp/.../ledger_wallet_cc"
    assert filepath_append_cc("/user/local/h.ledger.wallet") == "/user/local/h.ledger_cc.wallet"


def test_encrypted():
    runner = CliRunner()
    result = runner.invoke(electrum_convert2cc, [encrypted_path, "--dry-run"])
    assert result.exit_code == 1
    assert "Failed to load wallet file" in result.output


def test_dry_run():
    runner = CliRunner()
    for pth in [ledger_path, trezor_path]:
        result = runner.invoke(electrum_convert2cc, [pth, "--dry-run"])
        assert result.exit_code == 0
        loaded = json.loads(result.output)
        assert isinstance(loaded, dict)
        keystore = loaded["keystore"]
        assert_keystore(keystore)


def test_outfile():
    runner = CliRunner()
    for pth, name in zip([ledger_path, trezor_path], ["ledger00", "trezor00"]):
        outfile_path = os.path.join(test_data_path, name)
        result = runner.invoke(electrum_convert2cc, [pth, "-o", outfile_path])
        assert result.exit_code == 0
        assert "New wallet file created: tests/test_data/{}\n".format(name) == result.output
        with open(outfile_path, "r") as f:
            res = json.loads(f.read())
        assert_keystore(res["keystore"])
        os.remove(outfile_path)


def test_outfile_same_as_file():
    runner = CliRunner()
    for pth in [ledger_path, trezor_path]:
        result = runner.invoke(electrum_convert2cc, [pth, "-o", pth])
        assert result.exit_code == 1
        assert "'FILE' and '--outfile' cannot be the same\n" == result.output


def test_no_options():
    runner = CliRunner()
    for pth in [ledger_path, trezor_path]:
        result = runner.invoke(electrum_convert2cc, [pth])
        new_pth = filepath_append_cc(pth)
        assert result.exit_code == 0
        assert "New wallet file created: {}\n".format(new_pth) == result.output
        with open(new_pth, "r") as f:
            res = json.loads(f.read())
        assert_keystore(res["keystore"])
        os.remove(new_pth)


def test_not_hww_wallet():
    runner = CliRunner()
    for pth in [bip32_path]:
        result = runner.invoke(electrum_convert2cc, [pth])
        assert result.exit_code == 1
        assert result.output == "convert2cc failed: Not a hardware wallet type\n"


def test_not_standard_wallet():
    runner = CliRunner()
    for name, pth in [("2fa", a2fa_path), ("imported", import_path)]:
        result = runner.invoke(electrum_convert2cc, [pth])
        assert result.exit_code == 1
        assert result.output == "convert2cc failed: Unsupported wallet type: {}\n".format(name)


def test_is_multisig_wallet():
    valid = ["2of3", "2of2", "35of50"]
    for val in valid:
        val = {"wallet_type": val}
        assert is_multisig_wallet(val) is True
    invalid = ["a2of3", "2ofo3", "2of3a", "aaa", "x", "of"]
    for val in invalid:
        val = {"wallet_type": val}
        assert is_multisig_wallet(val) is False


def test_is_multisig_wallet_key():
    valid = ["x1/", "x2/", "x30/", "x156/"]
    for val in valid:
        assert is_multisig_wallet_key(val) is True
    invalid = ["1/", "x/", "xxxx", "aaa", "x", "of", "ax1/", "x1/a", "x1a/"]
    for val in invalid:
        assert is_multisig_wallet_key(val) is False


def test_multisig():
    runner = CliRunner()
    result = runner.invoke(electrum_convert2cc, [multi3of5_path, "-k", "hw_type", "-v", "ledger"])
    assert result.exit_code == 0
    new_pth = filepath_append_cc(multi3of5_path)
    assert "New wallet file created: {}\n".format(new_pth) == result.output
    with open(new_pth, "r") as f:
        res = json.loads(f.read())
    # ledger is x2/ entry
    assert_keystore(res["x2/"])
    # make sure other entries are unchanged
    assert res["x3/"]["hw_type"] == "trezor"
    os.remove(new_pth)

    result = runner.invoke(electrum_convert2cc, [multi3of5_path, "-k", "root_fingerprint", "-v", "7633218e"])
    assert result.exit_code == 1
    assert "Found 2 keystores" in result.output


