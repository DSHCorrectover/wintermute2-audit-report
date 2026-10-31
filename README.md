# Wintermute 2 Profanity Vulnerability Audit

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: Auditing](https://img.shields.io/badge/status-auditing-orange.svg)]()

> **Independent cryptographic audit of the Profanity vanity-address generator vulnerability exploited in the Wintermute 2 incident (June 2022).**

This repository contains the **verification tooling and methodology documentation** for our independent audit. The brute-force seed-recovery engine remains private under responsible-disclosure practices.

---

## The Incident

On **10 June 2022**, Wintermute's hot wallet (`0x000002...080a`) was drained of **~$160M** in tokens. The root cause was later traced to the **[Profanity](https://github.com/johguse/profanity)** vanity-address generator, which used a **32-bit seeded MT19937_64** to derive 256-bit private keys. This reduced the effective entropy from 2^256 to **2^32**, making the keys recoverable by brute force.

**Victim address:**
```
0x000002Cba8DfB0a86A47a415592835E17fac080a
```

## What This Repository Contains

| Component | Description |
|-----------|-------------|
| `verify.py` | **Read-only verification tool**: given a candidate `(seed, iterator)` pair, deterministically derives the Ethereum address and checks for a match. |
| `test_vectors.json` | Known-correct test vectors from independent sources (e.g. Safeheron research). |
| `docs/METHODOLOGY.md` | Full mathematical derivation of the attack path, from `std::random_device` 32-bit seed to Profanity's `createSeed()` output. |
| `Wintermute2_Audit_Report.pdf` | *(To be published after seed recovery is verified)* |

## What This Repository Does NOT Contain

- :x: The brute-force seed-search engine (kept private for responsible disclosure)
- :x: Pre-computed lookup tables or comb-method optimisations
- :x: Any recovered private keys or raw seed values

## Quick Start

```bash
# 1. Install dependencies
pip install pycryptodome

# 2. Run built-in test vectors
python3 verify.py --test-vectors

# 3. Verify a candidate (seed, iterator) pair
python3 verify.py --seed 12345 --iterator 5
```

## Mathematical Attack Path (Summary)

```
std::random_device (32-bit) 
    |
seed -> MT19937_64(seed)
    |
4 x uint64 -> 256-bit private_key_seed
    |
private_key = private_key_seed + iterator   (iterator in [0, ~2M])
    |
secp256k1 scalar multiplication -> public_key
    |
keccak256(public_key)[12:] -> Ethereum address
```

The critical flaw: `std::random_device` on many platforms is **not cryptographically secure** and returns only 32 bits of entropy. Profanity used this 32-bit value as the sole seed for MT19937_64, making the entire 2^32 seed space searchable.

For the full derivation, see [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

## Verification Methodology

Our audit follows a **zero-trust, reproducible** approach:

1. **Independent re-implementation**: Pure-Python secp256k1 + MT19937_64, zero external crypto dependencies, cross-validated against C++11 reference outputs.
2. **On-chain verification**: Every candidate address is checked against live Ethereum mainnet state.
3. **Adversarial testing**: Known test vectors from Safeheron's public research are used to continuously validate correctness.

## Audit Status

| Milestone | Status |
|-----------|--------|
| Vulnerability analysis | :white_check_mark: Complete |
| Mathematical derivation | :white_check_mark: Complete |
| Verification tooling | :white_check_mark: Complete |
| Seed-space brute-force | :lock: **In progress (private infrastructure)** |
| On-chain verification | :hourglass: Awaiting seed recovery |
| Final audit report | :hourglass: Awaiting verification |

## Responsible Disclosure

The brute-force engine is kept private because:
1. Profanity-generated addresses may still hold funds across multiple chains.
2. Public release of a turnkey seed-recovery tool would enable indiscriminate scanning of all historical vanity addresses.
3. Wintermute 2 is an active incident; the recovered key must be handled with extreme care.

If you are a **legitimate security researcher** or **affected party** and require access to the verification infrastructure, please contact us via the email in our GitHub profile.

## References

- [Safeheron - Profanity Vulnerability Research](https://github.com/safeheron/profanity-vanity-research)
- [Wintermute 2 Incident Post-Mortem](https://medium.com/@Wintermute_T)
- [Profanity GitHub Repository](https://github.com/johguse/profanity)
- [C++11 MT19937_64 Reference](https://en.cppreference.com/w/cpp/numeric/random/mersenne_twister_engine)

## License

MIT - See [LICENSE](LICENSE) for details.

## Acknowledgements

- **Safeheron** for their public research and test vectors.
- The **Ethereum security community** for collaborative incident response.

---

*This audit is conducted independently by Correctover. It is not affiliated with Wintermute, Profanity, or Safeheron.*
