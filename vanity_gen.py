#!/usr/bin/env python3
"""
Vanity cryptocurrency address generator.

Generates addresses whose prefix matches a user-supplied pattern.
Intended for generating addresses for your own wallets only.

Supported currencies: BTC, LTC, DOGE, DASH, ZEC, ETH
"""

import hashlib
import os
import sys
import argparse
import threading
import time
from typing import Optional, Tuple

try:
    import ecdsa
except ImportError:
    sys.exit("Missing dependency. Run: pip install ecdsa")

try:
    import base58
except ImportError:
    sys.exit("Missing dependency. Run: pip install base58")

try:
    from Crypto.Hash import keccak as _keccak_mod
except ImportError:
    sys.exit("Missing dependency. Run: pip install pycryptodome")

# ---------------------------------------------------------------------------
# Elliptic curve helpers
# ---------------------------------------------------------------------------

_CURVE = ecdsa.SECP256k1


def _generate_private_key() -> bytes:
    """Return a cryptographically random 32-byte secp256k1 private key."""
    while True:
        key = os.urandom(32)
        if 0 < int.from_bytes(key, "big") < _CURVE.order:
            return key


def _private_to_public_compressed(private_key: bytes) -> bytes:
    """Derive the compressed public key (33 bytes) from a private key."""
    sk = ecdsa.SigningKey.from_string(private_key, curve=_CURVE)
    vk = sk.get_verifying_key().to_string()  # 64 bytes: x || y
    prefix = b"\x02" if vk[63] % 2 == 0 else b"\x03"
    return prefix + vk[:32]


def _private_to_public_uncompressed(private_key: bytes) -> bytes:
    """Derive the uncompressed public key (64 bytes, x||y) from a private key."""
    sk = ecdsa.SigningKey.from_string(private_key, curve=_CURVE)
    return sk.get_verifying_key().to_string()


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _ripemd160(data: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(data)
    return h.digest()


def _hash160(data: bytes) -> bytes:
    """SHA-256 followed by RIPEMD-160 (standard Bitcoin hash160)."""
    return _ripemd160(_sha256(data))


def _double_sha256_checksum(payload: bytes) -> bytes:
    return _sha256(_sha256(payload))[:4]


def _keccak256(data: bytes) -> bytes:
    k = _keccak_mod.new(digest_bits=256)
    k.update(data)
    return k.digest()


# ---------------------------------------------------------------------------
# Address & WIF encoding
# ---------------------------------------------------------------------------

def _p2pkh_address(pubkey: bytes, version_byte: int) -> str:
    """Encode a P2PKH address with the given 1-byte version."""
    payload = bytes([version_byte]) + _hash160(pubkey)
    return base58.b58encode(payload + _double_sha256_checksum(payload)).decode()


def _zec_t1_address(pubkey: bytes) -> str:
    """Encode a Zcash transparent t1 (P2PKH) address (2-byte version 0x1CB8)."""
    payload = bytes([0x1C, 0xB8]) + _hash160(pubkey)
    return base58.b58encode(payload + _double_sha256_checksum(payload)).decode()


def _eth_address(private_key: bytes) -> str:
    """Derive an Ethereum address (checksummed hex with 0x prefix)."""
    pub_uncompressed = _private_to_public_uncompressed(private_key)  # 64 bytes
    addr_bytes = _keccak256(pub_uncompressed)[-20:]
    return "0x" + addr_bytes.hex()


def _wif_encode(private_key: bytes, version_byte: int) -> str:
    """Encode a private key as WIF (compressed key flag included)."""
    payload = bytes([version_byte]) + private_key + b"\x01"  # compressed flag
    return base58.b58encode(payload + _double_sha256_checksum(payload)).decode()


# ---------------------------------------------------------------------------
# Per-currency configuration
# ---------------------------------------------------------------------------

# (address_version_byte, wif_version_byte, address_prefix_for_display)
_COIN_CONFIG = {
    "BTC":  (0x00, 0x80, "1"),
    "LTC":  (0x30, 0xB0, "L"),
    "DOGE": (0x1E, 0x9E, "D"),
    "DASH": (0x4C, 0xCC, "X"),
}

SUPPORTED = {
    "BTC":  "Bitcoin",
    "LTC":  "Litecoin",
    "DOGE": "Dogecoin",
    "DASH": "Dash",
    "ZEC":  "Zcash (transparent t1 addresses)",
    "ETH":  "Ethereum",
}


def generate_address(currency: str) -> Tuple[str, str, Optional[str]]:
    """
    Generate a random address for *currency*.

    Returns ``(address, private_key_hex, wif_or_None)``.
    ETH does not use WIF; its third element is ``None``.
    """
    priv = _generate_private_key()

    if currency == "ETH":
        return _eth_address(priv), priv.hex(), None

    if currency == "ZEC":
        pub = _private_to_public_compressed(priv)
        return _zec_t1_address(pub), priv.hex(), _wif_encode(priv, 0x80)

    addr_ver, wif_ver, _ = _COIN_CONFIG[currency]
    pub = _private_to_public_compressed(priv)
    return _p2pkh_address(pub, addr_ver), priv.hex(), _wif_encode(priv, wif_ver)


# ---------------------------------------------------------------------------
# Vanity search
# ---------------------------------------------------------------------------

def _worker(
    currency: str,
    prefix: str,
    case_sensitive: bool,
    result: list,
    total_attempts: list,
    counter_lock: threading.Lock,
    stop: threading.Event,
) -> None:
    target = prefix if case_sensitive else prefix.lower()
    local_attempts = 0
    while not stop.is_set():
        addr, priv_hex, wif = generate_address(currency)
        local_attempts += 1
        cmp = addr if case_sensitive else addr.lower()
        if cmp.startswith(target):
            with counter_lock:
                total_attempts[0] += local_attempts
                result.append((addr, priv_hex, wif))
            stop.set()
            return
    # Thread stopped without finding a match: contribute its partial count.
    with counter_lock:
        total_attempts[0] += local_attempts


def find_vanity(
    currency: str,
    prefix: str,
    *,
    case_sensitive: bool = True,
    threads: int = 1,
) -> dict:
    """
    Search for a vanity address matching *prefix* for *currency*.

    Returns a dict with keys:
        ``currency``, ``address``, ``private_key_hex``,
        ``wif`` (all currencies except ETH), ``attempts``.
    """
    currency = currency.upper()
    if currency not in SUPPORTED:
        raise ValueError(
            f"Unsupported currency '{currency}'. "
            f"Supported: {', '.join(SUPPORTED)}"
        )
    if threads < 1:
        raise ValueError(f"threads must be at least 1, got {threads}")

    results: list = []
    total_attempts: list = [0]
    counter_lock = threading.Lock()
    stop = threading.Event()
    workers = [
        threading.Thread(
            target=_worker,
            args=(currency, prefix, case_sensitive, results,
                  total_attempts, counter_lock, stop),
            daemon=True,
        )
        for _ in range(threads)
    ]
    for w in workers:
        w.start()
    for w in workers:
        w.join()

    addr, priv_hex, wif = results[0]
    out = {
        "currency": currency,
        "address": addr,
        "private_key_hex": priv_hex,
        "attempts": total_attempts[0],
    }
    if wif is not None:
        out["wif"] = wif
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    supported_list = "\n".join(f"  {k:6} – {v}" for k, v in SUPPORTED.items())
    parser = argparse.ArgumentParser(
        description=(
            "Vanity cryptocurrency address generator.\n"
            "Generates addresses for your own wallets whose prefix matches\n"
            "the pattern you choose."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            f"Supported currencies:\n{supported_list}\n\n"
            "Examples:\n"
            "  python vanity_gen.py --currency BTC  --prefix 1Love\n"
            "  python vanity_gen.py --currency ETH  --prefix 0xdead "
            "--no-case-sensitive\n"
            "  python vanity_gen.py --currency DOGE --prefix DWoof "
            "--threads 4\n"
            "  python vanity_gen.py --currency ZEC  --prefix t1Fun\n"
        ),
    )
    parser.add_argument(
        "--currency", "-c",
        required=True,
        metavar="COIN",
        help="Currency code (BTC, ETH, LTC, DOGE, DASH, ZEC)",
    )
    parser.add_argument(
        "--prefix", "-p",
        required=True,
        help="Desired address prefix",
    )
    parser.add_argument(
        "--threads", "-t",
        type=int,
        default=1,
        metavar="N",
        help="Worker threads (default: 1)",
    )
    parser.add_argument(
        "--no-case-sensitive",
        dest="case_sensitive",
        action="store_false",
        help="Case-insensitive prefix matching",
    )
    parser.set_defaults(case_sensitive=True)
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    currency = args.currency.upper()
    if currency not in SUPPORTED:
        parser.error(
            f"Unsupported currency '{currency}'. "
            f"Supported: {', '.join(SUPPORTED)}"
        )

    cs_label = "case-sensitive" if args.case_sensitive else "case-insensitive"
    print(
        f"Searching for {SUPPORTED[currency]} address with prefix "
        f"'{args.prefix}' ({cs_label}) using {args.threads} thread(s)…"
    )

    t0 = time.monotonic()
    result = find_vanity(
        currency,
        args.prefix,
        case_sensitive=args.case_sensitive,
        threads=args.threads,
    )
    elapsed = time.monotonic() - t0

    print(f"\nFound after {result['attempts']:,} attempt(s) in {elapsed:.2f}s\n")
    print(f"  Currency    : {result['currency']}")
    print(f"  Address     : {result['address']}")
    print(f"  Private key : {result['private_key_hex']}")
    if "wif" in result:
        print(f"  WIF         : {result['wif']}")
    print()
    print("⚠  Keep your private key / WIF secret and never share it.")


if __name__ == "__main__":
    main()
