"""
Tests for vanity_gen.py
"""
import pytest
from vanity_gen import (
    _generate_private_key,
    _private_to_public_compressed,
    _private_to_public_uncompressed,
    _hash160,
    _p2pkh_address,
    _zec_t1_address,
    _eth_address,
    _wif_encode,
    generate_address,
    find_vanity,
    SUPPORTED,
    _COIN_CONFIG,
)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def test_private_key_is_32_bytes():
    assert len(_generate_private_key()) == 32


def test_private_key_is_random():
    keys = {_generate_private_key() for _ in range(10)}
    assert len(keys) == 10  # all unique


def test_compressed_public_key_length():
    priv = _generate_private_key()
    pub = _private_to_public_compressed(priv)
    assert len(pub) == 33
    assert pub[0] in (0x02, 0x03)


def test_uncompressed_public_key_length():
    priv = _generate_private_key()
    pub = _private_to_public_uncompressed(priv)
    assert len(pub) == 64


def test_hash160_length():
    assert len(_hash160(b"test")) == 20


# ---------------------------------------------------------------------------
# Address prefixes
# ---------------------------------------------------------------------------

def test_btc_address_prefix():
    addr, _, wif = generate_address("BTC")
    assert addr.startswith("1")
    assert wif is not None


def test_ltc_address_prefix():
    addr, _, wif = generate_address("LTC")
    assert addr.startswith("L")
    assert wif is not None


def test_doge_address_prefix():
    addr, _, wif = generate_address("DOGE")
    assert addr.startswith("D")
    assert wif is not None


def test_dash_address_prefix():
    addr, _, wif = generate_address("DASH")
    assert addr.startswith("X")
    assert wif is not None


def test_zec_address_prefix():
    addr, _, wif = generate_address("ZEC")
    assert addr.startswith("t1")
    assert wif is not None


def test_eth_address_prefix():
    addr, priv_hex, wif = generate_address("ETH")
    assert addr.startswith("0x")
    assert len(addr) == 42  # 0x + 40 hex chars
    assert wif is None  # ETH has no WIF


def test_all_supported_currencies_generate_address():
    for currency in SUPPORTED:
        addr, priv_hex, _ = generate_address(currency)
        assert isinstance(addr, str) and len(addr) > 0
        assert len(priv_hex) == 64  # 32 bytes hex


# ---------------------------------------------------------------------------
# WIF encoding
# ---------------------------------------------------------------------------

def test_wif_starts_with_correct_prefix():
    priv = _generate_private_key()
    wif_btc = _wif_encode(priv, 0x80)
    # Compressed WIF for mainnet BTC starts with K or L
    assert wif_btc[0] in ("K", "L")


# ---------------------------------------------------------------------------
# find_vanity
# ---------------------------------------------------------------------------

def test_find_vanity_btc_trivial_prefix():
    result = find_vanity("BTC", "1")
    assert result["address"].startswith("1")
    assert "wif" in result
    assert len(result["private_key_hex"]) == 64
    assert result["attempts"] >= 1


def test_find_vanity_eth_trivial_prefix():
    result = find_vanity("ETH", "0x")
    assert result["address"].startswith("0x")
    assert "wif" not in result
    assert result["attempts"] >= 1


def test_find_vanity_ltc_trivial_prefix():
    result = find_vanity("LTC", "L")
    assert result["address"].startswith("L")


def test_find_vanity_doge_trivial_prefix():
    result = find_vanity("DOGE", "D")
    assert result["address"].startswith("D")


def test_find_vanity_dash_trivial_prefix():
    result = find_vanity("DASH", "X")
    assert result["address"].startswith("X")


def test_find_vanity_zec_trivial_prefix():
    result = find_vanity("ZEC", "t1")
    assert result["address"].startswith("t1")


def test_find_vanity_case_insensitive():
    result = find_vanity("BTC", "1", case_sensitive=False)
    assert result["address"].lower().startswith("1")


def test_find_vanity_multi_thread():
    result = find_vanity("BTC", "1", threads=2)
    assert result["address"].startswith("1")
    assert result["attempts"] >= 1


def test_find_vanity_unsupported_raises():
    with pytest.raises(ValueError, match="Unsupported currency"):
        find_vanity("XYZ", "1")


def test_find_vanity_negative_threads_raises():
    with pytest.raises(ValueError, match="threads must be at least 1"):
        find_vanity("BTC", "1", threads=-1)


def test_find_vanity_returns_currency_key():
    result = find_vanity("BTC", "1")
    assert result["currency"] == "BTC"
