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

/** AuthScript testnet bech32m HRP. */
export const AUTHSCRIPT_TESTNET_HRP = 'tnq';

/** Build a base58check "t..." testnet P2PKH address from a raw 20-byte PKH. */
export function testnetP2PKHAddress(pkh20: Uint8Array): string {
  return bs58check.encode(new Uint8Array([LEGACY_TESTNET_PREFIX, ...pkh20]));
}

/** Build a bech32m "tnq1..." testnet AuthScript address for a 32-byte program. */
export function testnetAuthScriptAddress(program32: Uint8Array): string {
  const words = [1, ...bech32m.toWords(Array.from(program32))];
  return bech32m.encode(AUTHSCRIPT_TESTNET_HRP, words);
}
