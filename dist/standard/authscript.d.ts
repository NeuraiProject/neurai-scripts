/**
 * AuthScript (witness v1) scriptPubKey + witness-stack builders.
 *
 * AuthScript outputs encode a 32-byte commitment in a witness v1 program:
 *   scriptPubKey = OP_1 0x20 <32-byte program>
 *
 * The program is `HASH160`/`SHA256` over a descriptor that depends on the
 * `auth_type` byte carried as the first witness-stack element at spend time.
 * This library only assembles the stack; computing the descriptor/commitment
 * and producing the signature live in neurai-key / neurai-sign-transaction.
 *
 * Auth type values (authoritative: Neurai `src/script/interpreter.cpp`,
 * cross-checked against `lib/neurai-key/src/shared/address.ts`):
 *
 *   0x00  NoAuth         — no signature; spend gated only by witnessScript
 *   0x01  PQ             — ML-DSA-44 signature (post-quantum)
 *   0x02  Legacy         — secp256k1 ECDSA signature (classic)
 *   0x03  RefScript      — NIP-015 reference-script spend (future)
 *
 * Witness stack (exact order consumed by the interpreter):
 *   [ auth_type, sig, pubkey, arg0, ..., argN, witnessScript ]
 *
 * NoAuth and RefScript spends omit the `sig`/`pubkey` items.
 */
export declare const AUTHSCRIPT_NOAUTH = 0;
export declare const AUTHSCRIPT_PQ = 1;
export declare const AUTHSCRIPT_LEGACY = 2;
/** NIP-015: reference-script spend mode. Not yet activated in consensus. */
export declare const AUTHSCRIPT_REF = 3;
export type AuthType = typeof AUTHSCRIPT_NOAUTH | typeof AUTHSCRIPT_PQ | typeof AUTHSCRIPT_LEGACY | typeof AUTHSCRIPT_REF;
export declare function encodeAuthScriptScriptPubKey(program: Uint8Array): Uint8Array;
export interface AuthScriptWitnessLegacyInput {
    /** DER-encoded secp256k1 signature WITH trailing sighash byte. */
    signature: Uint8Array;
    /** Compressed (33B) or uncompressed (65B) secp256k1 public key. */
    pubKey: Uint8Array;
    /** Additional items consumed by the witnessScript, in bottom-to-top order. */
    args?: Uint8Array[];
    /** The full witnessScript whose hash equals the program of the output. */
    witnessScript: Uint8Array;
}
export interface AuthScriptWitnessPQInput {
    /** ML-DSA-44 signature (~2421 B) WITH trailing sighash byte. */
    signature: Uint8Array;
    /** Versioned PQ pubkey (1-byte prefix + 1312-byte ML-DSA-44 key ≈ 1313 B). */
    pubKey: Uint8Array;
    args?: Uint8Array[];
    witnessScript: Uint8Array;
}
export interface AuthScriptWitnessNoAuthInput {
    args?: Uint8Array[];
    witnessScript: Uint8Array;
}
export interface AuthScriptWitnessRefInput {
    /** Index into tx.vrefin where the reference-script carrier lives. */
    refIndex: number;
    args?: Uint8Array[];
}
/**
 * Build the witness stack for a legacy ECDSA AuthScript spend.
 *
 * Returns an array of raw stack elements. Serialization of the witness
 * (compact-size item count + per-item length-prefixes) is the caller's
 * responsibility — neurai-create-transaction handles it at tx-assembly time.
 */
export declare function buildAuthScriptWitnessLegacy(input: AuthScriptWitnessLegacyInput): Uint8Array[];
/**
 * Build the witness stack for a PQ (ML-DSA-44) AuthScript spend.
 * NIP-018 must be active: both signature and pubKey are pushed as single
 * stack elements and may each be up to 3072 B.
 */
export declare function buildAuthScriptWitnessPQ(input: AuthScriptWitnessPQInput): Uint8Array[];
/**
 * Build the witness stack for a NoAuth AuthScript spend. The spend is gated
 * by the witnessScript alone (covenants, hash-locks, time-locks, ...); no
 * signature or public key is carried.
 */
export declare function buildAuthScriptWitnessNoAuth(input: AuthScriptWitnessNoAuthInput): Uint8Array[];
/**
 * Build the witness stack for a NIP-015 reference-script spend. The last
 * item is the 4-byte little-endian index into `tx.vrefin` that locates the
 * reference-script carrier output; the interpreter resolves the `refScript`
 * from that carrier at validation time.
 *
 * NOTE: NIP-015 is not yet activated in consensus. This builder emits the
 * spec-conformant witness for forward compatibility and testnet experiments.
 */
export declare function buildAuthScriptWitnessRef(input: AuthScriptWitnessRefInput): Uint8Array[];
