from ckcc.utils import filepath_append_cc


def test_filepath_append_cc():
    assert filepath_append_cc("ledger_wallet") == "ledger_wallet_cc"
    assert filepath_append_cc("ledger_wallet.json") == "ledger_wallet_cc.json"
    assert filepath_append_cc("ledger wallet.json") == "ledger wallet_cc.json"
    assert filepath_append_cc("/ledger_wallet") == "/ledger_wallet_cc"
    assert filepath_append_cc("/tmp/.../ledger_wallet") == "/tmp/.../ledger_wallet_cc"
    assert filepath_append_cc("/user/local/h.ledger.wallet") == "/user/local/h.ledger_cc.wallet"
