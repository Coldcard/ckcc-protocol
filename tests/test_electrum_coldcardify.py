import os
import json
import shutil
import pytest
from click.testing import CliRunner

from ckcc.cli import electrum_coldcardify


# expecting cwd to be ckcc-protocol
test_data_path = os.path.join("tests", "test_data")
encrypted_path = os.path.join(test_data_path, "encrypted")
ledger_path = os.path.join(test_data_path, "ledger")
trezor_path = os.path.join(test_data_path, "trezor")


def assert_keystore(keystore):
    assert keystore["hw_type"] == "coldcard"
    assert "cfg" not in keystore
    assert keystore["label"] == "Coldcard {}".format(keystore["root_fingerprint"])
    assert keystore["soft_device_id"] is None
    # as this is run without coldcard connected - no ckcc_xpub
    assert "ckcc_xpub" not in keystore


def test_encrypted():
    runner = CliRunner()
    result = runner.invoke(electrum_coldcardify, [encrypted_path, "--dry-run"])
    assert result.exit_code == 1
    assert "Failed to load wallet file" in result.output


def test_no_op():
    runner = CliRunner()
    for pth in [ledger_path, trezor_path]:
        result = runner.invoke(electrum_coldcardify, [pth, "--dry-run"])
        assert result.exit_code == 0
        loaded = eval(result.output)
        assert isinstance(loaded, dict)
        keystore = loaded["keystore"]
        assert_keystore(keystore)


def test_outfile():
    runner = CliRunner()
    for pth, name in zip([ledger_path, trezor_path], ["ledger00", "trezor00"]):
        outfile_path = os.path.join(test_data_path, name)
        result = runner.invoke(electrum_coldcardify, [pth, "-o", outfile_path])
        assert result.exit_code == 0
        assert "New wallet file created: tests/test_data/{}\n".format(name) == result.output
        with open(outfile_path, "r") as f:
            res = json.loads(f.read())
        assert_keystore(res["keystore"])
        os.remove(outfile_path)


def test_inplace():
    runner = CliRunner()
    for pth in [ledger_path, trezor_path]:
        # first copy file before changing it in place
        new_pth = shutil.copy(pth, pth + "000")
        result = runner.invoke(electrum_coldcardify, [new_pth])
        assert result.exit_code == 0
        assert "Backed up original wallet file to" in result.output
        assert "{} coldcardified".format(new_pth) in result.output
        with open(new_pth, "r") as f:
            res = json.loads(f.read())
        assert_keystore(res["keystore"])
        os.remove(new_pth)
