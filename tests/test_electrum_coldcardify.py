import os
import json
from click.testing import CliRunner

from ckcc.cli import electrum_coldcardify
from ckcc.utils import filepath_append_cc


# expecting cwd to be ckcc-protocol
test_data_path = os.path.join("tests", "test_data")
encrypted_path = os.path.join(test_data_path, "encrypted")
ledger_path = os.path.join(test_data_path, "ledger")
trezor_path = os.path.join(test_data_path, "trezor.json")


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


def test_dry_run():
    runner = CliRunner()
    for pth in [ledger_path, trezor_path]:
        result = runner.invoke(electrum_coldcardify, [pth, "--dry-run"])
        assert result.exit_code == 0
        loaded = json.loads(result.output)
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


def test_outfile_same_as_file():
    runner = CliRunner()
    for pth in [ledger_path, trezor_path]:
        result = runner.invoke(electrum_coldcardify, [pth, "-o", pth])
        assert result.exit_code == 1
        assert "'FILE' and '--outfile' cannot be the same\n" == result.output


def test_no_options():
    runner = CliRunner()
    for pth in [ledger_path, trezor_path]:
        result = runner.invoke(electrum_coldcardify, [pth])
        new_pth = filepath_append_cc(pth)
        assert result.exit_code == 0
        assert "New wallet file created: {}\n".format(new_pth) == result.output
        with open(new_pth, "r") as f:
            res = json.loads(f.read())
        assert_keystore(res["keystore"])
        os.remove(new_pth)
