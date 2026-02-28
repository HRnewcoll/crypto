# crypto — Vanity Address Generator

Generate cryptocurrency addresses whose prefix matches a pattern you choose,
for use with your own wallets.

## Supported currencies

| Code | Currency                        | Address format  |
|------|---------------------------------|-----------------|
| BTC  | Bitcoin                         | starts with `1` |
| LTC  | Litecoin                        | starts with `L` |
| DOGE | Dogecoin                        | starts with `D` |
| DASH | Dash                            | starts with `X` |
| ZEC  | Zcash (transparent t1)          | starts with `t1`|
| ETH  | Ethereum                        | starts with `0x`|

## Requirements

```
pip install -r requirements.txt
```

Dependencies: `ecdsa`, `base58`, `pycryptodome`

## Usage

```
python vanity_gen.py --currency <COIN> --prefix <PREFIX> [options]
```

| Option | Short | Description |
|--------|-------|-------------|
| `--currency COIN` | `-c` | Currency code (BTC, ETH, LTC, DOGE, DASH, ZEC) |
| `--prefix PREFIX` | `-p` | Desired address prefix |
| `--threads N` | `-t` | Worker threads (default: 1) |
| `--no-case-sensitive` | | Case-insensitive prefix matching |

### Examples

```bash
# Bitcoin address starting with 1Love
python vanity_gen.py --currency BTC --prefix 1Love

# Ethereum address starting with 0xdead (case-insensitive)
python vanity_gen.py --currency ETH --prefix 0xdead --no-case-sensitive

# Dogecoin address with 4 threads
python vanity_gen.py --currency DOGE --prefix DWoof --threads 4

# Zcash transparent address
python vanity_gen.py --currency ZEC --prefix t1Fun
```

### Example output

```
Searching for Bitcoin address with prefix '1Love' (case-sensitive) using 1 thread(s)…

Found after 14,823 attempt(s) in 2.41s

  Currency    : BTC
  Address     : 1LoveTszRFQMK2A5b9c7mVQ5APoBqrpsPE
  Private key : 3a9f...
  WIF         : KyDT...

⚠  Keep your private key / WIF secret and never share it.
```

## Security notes

* The address and its private key/WIF are generated locally — nothing is sent
  to any server.
* **Never share your private key or WIF with anyone.**
* Longer prefixes take exponentially more time to find. Each additional
  Base58 character multiplies search time by ~58×.

## Running tests

```bash
pytest test_vanity_gen.py -v
```
