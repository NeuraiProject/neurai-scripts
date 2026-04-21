/**
 * Low-level Script assembler. Emits the exact byte layout expected by the
 * Neurai interpreter: pushdata prefixes follow the same rules as Bitcoin
 * (direct push for 1..75 bytes, OP_PUSHDATA1/2/4 otherwise), and integers
 * are minimally-encoded as CScriptNum.
 */
/**
 * Minimal CScriptNum encoding (Bitcoin consensus rules).
 *
 * - 0 → empty vector
 * - 1..16 → single opcode OP_1..OP_16 (handled in `pushInt`, not here)
 * - -1 → OP_1NEGATE (handled in `pushInt`)
 * - otherwise: sign-magnitude little-endian, with a sign bit on the last byte
 */
export declare function encodeScriptNum(value: bigint | number): Uint8Array;
/**
 * Emit a pushdata opcode followed by the payload. Chooses the shortest
 * valid encoding.
 *
 * Neurai Script caps stack elements at `MAX_SCRIPT_ELEMENT_SIZE = 520`
 * bytes by default, but NIP-18 raises the cap to
 * `MAX_PQ_SCRIPT_ELEMENT_SIZE = 3072` whenever
 * `SCRIPT_VERIFY_CHECKSIGFROMSTACK` is active (testnet today, mainnet once
 * the CSFS fork lands). The builder here emits pushes up to 3072 bytes so
 * it can target either regime; legacy scripts should stay under 520 bytes
 * per push, and the node will reject anything larger if the CSFS flag is
 * not set during evaluation.
 */
export declare function pushBytes(data: Uint8Array): Uint8Array;
/**
 * Emit a minimally-encoded integer push. Uses OP_1NEGATE, OP_0 and OP_1..OP_16
 * when available to match how the node's own templates look on the wire.
 */
export declare function pushInt(value: bigint | number): Uint8Array;
export declare function pushHex(hex: string): Uint8Array;
/** Fluent assembler for readable script definitions. */
export declare class ScriptBuilder {
    private readonly parts;
    op(...opcodes: number[]): this;
    pushInt(value: bigint | number): this;
    pushBytes(data: Uint8Array): this;
    pushHex(hex: string): this;
    raw(bytes: Uint8Array): this;
    build(): Uint8Array;
    buildHex(): string;
}
