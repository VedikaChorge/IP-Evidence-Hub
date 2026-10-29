import pytest
from web3 import Web3

import chain

DIGEST = "ab" * 32


def test_from_env_mainnet_selects_mst_mainnet_settings(monkeypatch):
    monkeypatch.setenv("MST_NETWORK", "mainnet")
    monkeypatch.setenv("CONTRACT_ADDRESS", "0x" + "ab" * 20)

    client = chain.from_env()

    assert client.network.chain_id == 4646
    assert client.network.tx_url("0x1") == "https://mstscan.com/tx/0x1"
    assert client.configured and not client.server_signer


@pytest.mark.parametrize("address", ["", "not-an-address", "0x1234"])
def test_from_env_missing_or_invalid_contract_address_is_unconfigured(monkeypatch, address):
    monkeypatch.setenv("CONTRACT_ADDRESS", address)

    assert not chain.from_env().configured


def test_from_env_unknown_network_raises(monkeypatch):
    monkeypatch.setenv("MST_NETWORK", "sepolia")

    with pytest.raises(ValueError):
        chain.from_env()


def test_calldata_encodes_register_evidence_call():
    client = chain.MSTChain(chain.Network.from_key("coral-testnet"), "0x" + "ab" * 20)

    data = client.calldata(DIGEST, "IPEH-1")

    selector = Web3.keccak(text="registerEvidence(bytes32,string)")[:4].hex()
    assert data.startswith("0x" + selector + DIGEST)
    assert b"IPEH-1".hex() in data
