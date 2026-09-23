/**
 * Test-only helpers for constructing Neurai addresses from raw bytes.
 *
 * These live in the test tree (not in `src/`) because the runtime library
 * intentionally does not pull in `bs58check` / `bech32` for address
 * encoding — callers already have them via their wallet stack. Tests do
 * need them to build synthetic addresses from known PKHs / programs, so
 * the deps are declared as `devDependencies` and wrapped here.
 */

import bs58check from 'bs58check';
import { bech32m } from 'bech32';

/**
 * Neurai legacy P2PKH testnet version byte. Source of truth:
 * `neurai-create-transaction/src/networks.ts`.
 */
export const LEGACY_TESTNET_PREFIX = 0x7f;

/** Generic AuthScript v1 testnet bech32m HRP (regtest shares it). */
export const AUTHSCRIPT_TESTNET_HRP = 'tnc';
/** Strict PQ witness v2 testnet HRP. */
export const PQ_TESTNET_HRP = 'tpq';
/** Strict ECDSA witness v3 testnet HRP. */
export const ECDSA_TESTNET_HRP = 'tnq';

/** Build a base58check "t..." testnet P2PKH address from a raw 20-byte PKH. */
export function testnetP2PKHAddress(pkh20: Uint8Array): string {
  return bs58check.encode(new Uint8Array([LEGACY_TESTNET_PREFIX, ...pkh20]));
}

/** Build a bech32m "tnc1p..." testnet generic AuthScript v1 address for a 32-byte program. */
export function testnetAuthScriptAddress(program32: Uint8Array): string {
  const words = [1, ...bech32m.toWords(Array.from(program32))];
  return bech32m.encode(AUTHSCRIPT_TESTNET_HRP, words);
}

/** Build a bech32m "tpq1z..." testnet strict PQ v2 address for a 32-byte program. */
export function testnetStrictPQAddress(program32: Uint8Array): string {
  return bech32m.encode(PQ_TESTNET_HRP, [2, ...bech32m.toWords(Array.from(program32))]);
}

/** Build a bech32m "tnq1r..." testnet strict ECDSA v3 address for a 32-byte program. */
export function testnetStrictECDSAAddress(program32: Uint8Array): string {
  return bech32m.encode(ECDSA_TESTNET_HRP, [3, ...bech32m.toWords(Array.from(program32))]);
}
