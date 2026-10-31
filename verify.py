#!/usr/bin/env python3
"""
Wintermute 2 Profanity Vulnerability — Verification Tool
=========================================================

Given a candidate (seed, iterator) pair, this script verifies whether
the resulting Ethereum address matches the Wintermute 2 victim:
    0x000002Cba8DfB0a86A47a415592835E17fac080a

This is a READ-ONLY verification tool. It does NOT perform brute-force
search over the 2^32 seed space. The search engine remains private for
responsible disclosure reasons.

Usage:
    python3 verify.py --seed 12345 --iterator 5
    python3 verify.py --test-vectors

Dependencies:
    pip install pycryptodome
"""

import argparse
import json

# -- secp256k1 ----------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)


def point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow((x2 - x1) % P, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def scalar_mul(k, p=None):
    if p is None:
        p = G
    r = None
    while k:
        if k & 1:
            r = point_add(r, p)
        p = point_add(p, p)
        k >>= 1
    return r


# -- MT19937_64 ---------------------------------------------------------------
class MT19937_64:
    """C++11-compatible MT19937_64 (period 2^19937-1, 64-bit output)."""
    W, N, M, R = 64, 312, 156, 31
    A = 0xB5026F5AA96619E9
    U, D, S, B, T, C, L = 29, 0x5555555555555555, 17, 0x71D67FFFEDA60000, 37, 0xFFF7EEE000000000, 43
    F = 6364136223846793005
    LOWER_MASK = (1 << R) - 1
    UPPER_MASK = (~LOWER_MASK) & ((1 << W) - 1)

    def __init__(self, seed=5489):
        self.mt = [0] * self.N
        self.index = self.N + 1
        self.seed(seed)

    def seed(self, seed):
        self.mt[0] = seed & ((1 << self.W) - 1)
        for i in range(1, self.N):
            prev = self.mt[i - 1]
            self.mt[i] = ((self.F * (prev ^ (prev >> (self.W - 2)))) + i) & ((1 << self.W) - 1)
        self.index = self.N

    def twist(self):
        for i in range(self.N):
            x = (self.mt[i] & self.UPPER_MASK) + (self.mt[(i + 1) % self.N] & self.LOWER_MASK)
            xA = x >> 1
            if x & 1:
                xA ^= self.A
            self.mt[i] = self.mt[(i + self.M) % self.N] ^ xA
            self.mt[i] &= ((1 << self.W) - 1)
        self.index = 0

    def __call__(self):
        if self.index >= self.N:
            self.twist()
        y = self.mt[self.index]
        self.index += 1
        y ^= (y >> self.U) & self.D
        y ^= (y << self.S) & self.B
        y ^= (y << self.T) & self.C
        y ^= (y >> self.L)
        return y & ((1 << self.W) - 1)


def profanity_seed_to_priv(seed):
    """Profanity createSeed(): 4x uint64 from MT19937_64(seed) -> 256-bit private key."""
    rng = MT19937_64(seed)
    r0 = rng()
    r1 = rng()
    r2 = rng()
    r3 = rng()
    return r0 | (r1 << 64) | (r2 << 128) | (r3 << 192)


# -- Ethereum address derivation ----------------------------------------------
def priv_to_address(priv):
    """secp256k1 priv -> pubkey -> keccak256 -> address (20 bytes)."""
    from Crypto.Hash import keccak
    pub = scalar_mul(priv)
    pub_bytes = pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big")
    h = keccak.new(digest_bits=256)
    h.update(pub_bytes)
    return "0x" + h.hexdigest()[-40:]


# -- Verification -------------------------------------------------------------
TARGET_ADDRESS = "0x000002Cba8DfB0a86A47a415592835E17fac080a"


def verify(seed, iterator):
    """
    Profanity computes: private_key = seed_priv + iterator
    Then derives the Ethereum address from that private key.
    """
    seed_priv = profanity_seed_to_priv(seed)
    full_priv = (seed_priv + iterator) % N
    addr = priv_to_address(full_priv)
    match = addr.lower() == TARGET_ADDRESS.lower()
    return {
        "seed": seed,
        "iterator": iterator,
        "seed_priv_hex": f"0x{seed_priv:064x}",
        "full_priv_hex": f"0x{full_priv:064x}",
        "derived_address": addr,
        "target_address": TARGET_ADDRESS,
        "match": match,
    }


# -- Test vectors -------------------------------------------------------------
TEST_VECTORS = [
    {
        "name": "Safeheron test vector #1",
        "seed": 12345,
        "iterator": 5,
        "note": "Known working pair from Safeheron profanity-vanity-research",
    },
    {
        "name": "Wintermute 2 target (awaiting result)",
        "seed": None,
        "iterator": None,
        "expected_address": TARGET_ADDRESS,
        "note": "The actual seed/iterator for this address is the subject of the audit.",
    },
]


def run_test_vectors():
    print("Running test vectors...\n")
    for tv in TEST_VECTORS:
        name = tv["name"]
        seed = tv["seed"]
        iterator = tv["iterator"]
        if seed is None or iterator is None:
            print(f"  [{name}]")
            print(f"    Status: SKIP (seed/iterator not yet disclosed)")
            print()
            continue
        result = verify(seed, iterator)
        print(f"  [{name}]")
        print(f"    Seed:     {seed}")
        print(f"    Iterator: {iterator}")
        print(f"    Address:  {result['derived_address']}")
        print(f"    Match:    {result['match']}")
        print()
    print("Done.")


# -- CLI ----------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify a (seed, iterator) pair against the Wintermute 2 target address.")
    parser.add_argument("--seed", type=int, required=False, help="MT19937_64 seed (uint32)")
    parser.add_argument("--iterator", type=int, required=False, help="Profanity iterator offset")
    parser.add_argument("--test-vectors", action="store_true", help="Run built-in test vectors")
    args = parser.parse_args()

    if args.test_vectors:
        run_test_vectors()
    elif args.seed is not None and args.iterator is not None:
        result = verify(args.seed, args.iterator)
        print(json.dumps(result, indent=2))
        if result["match"]:
            print("\nMATCH: This (seed, iterator) pair produces the Wintermute 2 victim address!")
        else:
            print(f"\nNO MATCH: Derived {result['derived_address']} != {TARGET_ADDRESS}")
    else:
        parser.print_help()
