/**
 * Minimal byte helpers. A subset of what `neurai-create-transaction` exposes,
 * duplicated here to keep this package free of runtime coupling beyond its
 * declared `dependencies` field. All sizes are little-endian, per Neurai.
 */
function ensureHex(hex, label = 'hex') {
    const normalized = String(hex || '').trim().toLowerCase();
    if (!/^[0-9a-f]*$/.test(normalized) || normalized.length % 2 !== 0) {
        throw new Error(`Invalid ${label}: expected even-length hex string`);
    }
    return normalized;
}
function hexToBytes(hex) {
    const normalized = ensureHex(hex);
    const bytes = new Uint8Array(normalized.length / 2);
    for (let i = 0; i < normalized.length; i += 2) {
        bytes[i / 2] = Number.parseInt(normalized.slice(i, i + 2), 16);
    }
    return bytes;
}
function bytesToHex(bytes) {
    return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}
function concatBytes(...parts) {
    const total = parts.reduce((sum, part) => sum + part.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}
function bytesEqual(a, b) {
    if (a.length !== b.length)
        return false;
    for (let i = 0; i < a.length; i += 1) {
        if (a[i] !== b[i])
            return false;
    }
    return true;
}

/**
 * Opcode constants for Neurai Script.
 *
 * Covers:
 *  - Classic Script opcodes used by covenants.
 *  - New opcodes activated in the `DePIN-Test` branch (BIP 119, BIP 347 and
 *    Neurai-specific introspection / asset / arithmetic additions).
 *
 * Authority: `src/script/script.h` (enum `opcodetype`) in the Neurai repo.
 * Reference: `doc/new-opcodes-depin-branch.md`.
 *
 * Disabled in consensus and intentionally omitted: OP_SUBSTR, OP_LEFT,
 * OP_RIGHT, OP_INVERT, OP_AND, OP_OR, OP_XOR, OP_2MUL, OP_2DIV, OP_LSHIFT,
 * OP_RSHIFT. Also omitted: OP_VER / OP_VERIF / OP_VERNOTIF (reserved), the
 * template-matching pseudo-opcodes (OP_SMALLINTEGER, OP_PUBKEYS,
 * OP_PUBKEYHASH, OP_PUBKEY) and OP_INVALIDOPCODE.
 */
// ---------- Push values ----------
const OP_0 = 0x00;
const OP_FALSE = OP_0;
const OP_PUSHDATA1 = 0x4c;
const OP_PUSHDATA2 = 0x4d;
const OP_PUSHDATA4 = 0x4e;
const OP_1NEGATE = 0x4f;
const OP_RESERVED = 0x50;
const OP_1 = 0x51;
const OP_TRUE = OP_1;
const OP_2 = 0x52;
const OP_3 = 0x53;
const OP_4 = 0x54;
const OP_5 = 0x55;
const OP_6 = 0x56;
const OP_7 = 0x57;
const OP_8 = 0x58;
const OP_9 = 0x59;
const OP_10 = 0x5a;
const OP_11 = 0x5b;
const OP_12 = 0x5c;
const OP_13 = 0x5d;
const OP_14 = 0x5e;
const OP_15 = 0x5f;
const OP_16 = 0x60;
// ---------- Control flow ----------
const OP_NOP = 0x61;
const OP_IF = 0x63;
const OP_NOTIF = 0x64;
const OP_ELSE = 0x67;
const OP_ENDIF = 0x68;
const OP_VERIFY = 0x69;
const OP_RETURN = 0x6a;
// ---------- Stack ----------
const OP_TOALTSTACK = 0x6b;
const OP_FROMALTSTACK = 0x6c;
const OP_2DROP = 0x6d;
const OP_2DUP = 0x6e;
const OP_3DUP = 0x6f;
const OP_2OVER = 0x70;
const OP_2ROT = 0x71;
const OP_2SWAP = 0x72;
const OP_IFDUP = 0x73;
const OP_DEPTH = 0x74;
const OP_DROP = 0x75;
const OP_DUP = 0x76;
const OP_NIP = 0x77;
const OP_OVER = 0x78;
const OP_PICK = 0x79;
const OP_ROLL = 0x7a;
const OP_ROT = 0x7b;
const OP_SWAP = 0x7c;
const OP_TUCK = 0x7d;
// ---------- Splice ----------
const OP_SIZE = 0x82;
// ---------- Bitwise / comparison ----------
const OP_EQUAL = 0x87;
const OP_EQUALVERIFY = 0x88;
// ---------- Unary numeric ----------
const OP_1ADD = 0x8b;
const OP_1SUB = 0x8c;
const OP_NEGATE = 0x8f;
const OP_ABS = 0x90;
const OP_NOT = 0x91;
const OP_0NOTEQUAL = 0x92;
// ---------- Arithmetic (64-bit after SCRIPT_VERIFY_64BIT_INTEGERS) ----------
const OP_ADD = 0x93;
const OP_SUB = 0x94;
const OP_MUL = 0x95;
const OP_DIV = 0x96;
const OP_MOD = 0x97;
// ---------- Boolean / numeric comparison ----------
const OP_BOOLAND = 0x9a;
const OP_BOOLOR = 0x9b;
const OP_NUMEQUAL = 0x9c;
const OP_NUMEQUALVERIFY = 0x9d;
const OP_NUMNOTEQUAL = 0x9e;
const OP_LESSTHAN = 0x9f;
const OP_GREATERTHAN = 0xa0;
const OP_LESSTHANOREQUAL = 0xa1;
const OP_GREATERTHANOREQUAL = 0xa2;
const OP_MIN = 0xa3;
const OP_MAX = 0xa4;
const OP_WITHIN = 0xa5;
// ---------- Crypto ----------
const OP_RIPEMD160 = 0xa6;
const OP_SHA1 = 0xa7;
const OP_SHA256 = 0xa8;
const OP_HASH160 = 0xa9;
const OP_HASH256 = 0xaa;
const OP_CODESEPARATOR = 0xab;
const OP_CHECKSIG = 0xac;
const OP_CHECKSIGVERIFY = 0xad;
const OP_CHECKMULTISIG = 0xae;
const OP_CHECKMULTISIGVERIFY = 0xaf;
// ---------- Expansion / NOPs ----------
// Only the NOPs not aliased by DePIN-Test opcodes are exported as NOPs.
//   OP_NOP2 == OP_CHECKLOCKTIMEVERIFY (0xb1)
//   OP_NOP3 == OP_CHECKSEQUENCEVERIFY (0xb2)
//   OP_NOP4 == OP_CHECKTEMPLATEVERIFY (0xb3)
//   OP_NOP5 == OP_CHECKSIGFROMSTACK  (0xb4)
//   OP_NOP6 == OP_TXHASH             (0xb5)
//   OP_NOP7 == OP_TXFIELD            (0xb6)
//   OP_NOP8 == OP_SPLIT              (0xb7)
const OP_NOP1 = 0xb0;
const OP_NOP9 = 0xb8;
const OP_NOP10 = 0xb9;
// ---------- Locktime ----------
const OP_CHECKLOCKTIMEVERIFY = 0xb1;
const OP_CHECKSEQUENCEVERIFY = 0xb2;
// ---------- Covenants & templates (DePIN-Test) ----------
const OP_CHECKTEMPLATEVERIFY = 0xb3; // BIP 119
const OP_CHECKSIGFROMSTACK = 0xb4;
// ---------- Transaction introspection (DePIN-Test) ----------
const OP_TXHASH = 0xb5;
const OP_TXFIELD = 0xb6;
const OP_TXLOCKTIME = 0xc5;
const OP_OUTPUTVALUE = 0xcc;
const OP_OUTPUTSCRIPT = 0xcd;
const OP_INPUTCOUNT = 0xd0;
const OP_OUTPUTCOUNT = 0xd1;
// ---------- Asset introspection (DePIN-Test) ----------
const OP_OUTPUTASSETFIELD = 0xce;
const OP_INPUTASSETFIELD = 0xcf;
const OP_XNA_ASSET = 0xc0;
// ---------- Reference inputs (DePIN-Test, NIP-017) ----------
const OP_REFINPUTFIELD = 0xd2;
const OP_REFINPUTASSETFIELD = 0xd3;
const OP_REFINPUTCOUNT = 0xd4;
// ---------- Byte manipulation (DePIN-Test) ----------
const OP_CAT = 0x7e;
const OP_SPLIT = 0xb7;
const OP_REVERSEBYTES = 0xbc;
// ---------- Selectors for OP_TXFIELD / OP_REFINPUTFIELD ----------
// Both opcodes share the same selector table (OP_TXFIELD on the spent UTXO,
// OP_REFINPUTFIELD on an output referenced via vrefin). Valid: 0x01..0x03.
const TXFIELD_VALUE = 0x01;
const TXFIELD_AUTHSCRIPT_COMMITMENT = 0x02;
const TXFIELD_SCRIPTPUBKEY = 0x03;
// ---------- Bitmask selectors for OP_TXHASH ----------
// The selector is a single byte where each bit selects which transaction
// field to include in the double-SHA256. Selector 0x00 is invalid; any
// non-zero combination is valid. 0xff = all eight fields.
const TXHASH_VERSION = 0x01;
const TXHASH_LOCKTIME = 0x02;
const TXHASH_INPUT_PREVOUTS = 0x04;
const TXHASH_INPUT_SEQUENCES = 0x08;
const TXHASH_OUTPUTS = 0x10;
const TXHASH_CURRENT_PREVOUT = 0x20;
const TXHASH_CURRENT_SEQUENCE = 0x40;
const TXHASH_CURRENT_INDEX = 0x80;
const TXHASH_ALL = 0xff;
// ---------- Selectors for OP_OUTPUTASSETFIELD / OP_INPUTASSETFIELD / OP_REFINPUTASSETFIELD ----------
// All three opcodes share the same selector table. Valid range: 0x01..0x07.
// Selector 0x05 is the boolean "has IPFS" flag; 0x06 is the IPFS hash
// payload; 0x07 is the asset operation type. (This matches the asset-op
// encoding in `src/assets/assets.cpp` and the NIP spec §3.1.)
const ASSETFIELD_NAME = 0x01;
const ASSETFIELD_AMOUNT = 0x02;
const ASSETFIELD_UNITS = 0x03;
const ASSETFIELD_REISSUABLE = 0x04;
const ASSETFIELD_HAS_IPFS = 0x05;
const ASSETFIELD_IPFS_HASH = 0x06;
const ASSETFIELD_TYPE = 0x07;

var opcodes = /*#__PURE__*/Object.freeze({
    __proto__: null,
    ASSETFIELD_AMOUNT: ASSETFIELD_AMOUNT,
    ASSETFIELD_HAS_IPFS: ASSETFIELD_HAS_IPFS,
    ASSETFIELD_IPFS_HASH: ASSETFIELD_IPFS_HASH,
    ASSETFIELD_NAME: ASSETFIELD_NAME,
    ASSETFIELD_REISSUABLE: ASSETFIELD_REISSUABLE,
    ASSETFIELD_TYPE: ASSETFIELD_TYPE,
    ASSETFIELD_UNITS: ASSETFIELD_UNITS,
    OP_0: OP_0,
    OP_0NOTEQUAL: OP_0NOTEQUAL,
    OP_1: OP_1,
    OP_10: OP_10,
    OP_11: OP_11,
    OP_12: OP_12,
    OP_13: OP_13,
    OP_14: OP_14,
    OP_15: OP_15,
    OP_16: OP_16,
    OP_1ADD: OP_1ADD,
    OP_1NEGATE: OP_1NEGATE,
    OP_1SUB: OP_1SUB,
    OP_2: OP_2,
    OP_2DROP: OP_2DROP,
    OP_2DUP: OP_2DUP,
    OP_2OVER: OP_2OVER,
    OP_2ROT: OP_2ROT,
    OP_2SWAP: OP_2SWAP,
    OP_3: OP_3,
    OP_3DUP: OP_3DUP,
    OP_4: OP_4,
    OP_5: OP_5,
    OP_6: OP_6,
    OP_7: OP_7,
    OP_8: OP_8,
    OP_9: OP_9,
    OP_ABS: OP_ABS,
    OP_ADD: OP_ADD,
    OP_BOOLAND: OP_BOOLAND,
    OP_BOOLOR: OP_BOOLOR,
    OP_CAT: OP_CAT,
    OP_CHECKLOCKTIMEVERIFY: OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKMULTISIG: OP_CHECKMULTISIG,
    OP_CHECKMULTISIGVERIFY: OP_CHECKMULTISIGVERIFY,
    OP_CHECKSEQUENCEVERIFY: OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG: OP_CHECKSIG,
    OP_CHECKSIGFROMSTACK: OP_CHECKSIGFROMSTACK,
    OP_CHECKSIGVERIFY: OP_CHECKSIGVERIFY,
    OP_CHECKTEMPLATEVERIFY: OP_CHECKTEMPLATEVERIFY,
    OP_CODESEPARATOR: OP_CODESEPARATOR,
    OP_DEPTH: OP_DEPTH,
    OP_DIV: OP_DIV,
    OP_DROP: OP_DROP,
    OP_DUP: OP_DUP,
    OP_ELSE: OP_ELSE,
    OP_ENDIF: OP_ENDIF,
    OP_EQUAL: OP_EQUAL,
    OP_EQUALVERIFY: OP_EQUALVERIFY,
    OP_FALSE: OP_FALSE,
    OP_FROMALTSTACK: OP_FROMALTSTACK,
    OP_GREATERTHAN: OP_GREATERTHAN,
    OP_GREATERTHANOREQUAL: OP_GREATERTHANOREQUAL,
    OP_HASH160: OP_HASH160,
    OP_HASH256: OP_HASH256,
    OP_IF: OP_IF,
    OP_IFDUP: OP_IFDUP,
    OP_INPUTASSETFIELD: OP_INPUTASSETFIELD,
    OP_INPUTCOUNT: OP_INPUTCOUNT,
    OP_LESSTHAN: OP_LESSTHAN,
    OP_LESSTHANOREQUAL: OP_LESSTHANOREQUAL,
    OP_MAX: OP_MAX,
    OP_MIN: OP_MIN,
    OP_MOD: OP_MOD,
    OP_MUL: OP_MUL,
    OP_NEGATE: OP_NEGATE,
    OP_NIP: OP_NIP,
    OP_NOP: OP_NOP,
    OP_NOP1: OP_NOP1,
    OP_NOP10: OP_NOP10,
    OP_NOP9: OP_NOP9,
    OP_NOT: OP_NOT,
    OP_NOTIF: OP_NOTIF,
    OP_NUMEQUAL: OP_NUMEQUAL,
    OP_NUMEQUALVERIFY: OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL: OP_NUMNOTEQUAL,
    OP_OUTPUTASSETFIELD: OP_OUTPUTASSETFIELD,
    OP_OUTPUTCOUNT: OP_OUTPUTCOUNT,
    OP_OUTPUTSCRIPT: OP_OUTPUTSCRIPT,
    OP_OUTPUTVALUE: OP_OUTPUTVALUE,
    OP_OVER: OP_OVER,
    OP_PICK: OP_PICK,
    OP_PUSHDATA1: OP_PUSHDATA1,
    OP_PUSHDATA2: OP_PUSHDATA2,
    OP_PUSHDATA4: OP_PUSHDATA4,
    OP_REFINPUTASSETFIELD: OP_REFINPUTASSETFIELD,
    OP_REFINPUTCOUNT: OP_REFINPUTCOUNT,
    OP_REFINPUTFIELD: OP_REFINPUTFIELD,
    OP_RESERVED: OP_RESERVED,
    OP_RETURN: OP_RETURN,
    OP_REVERSEBYTES: OP_REVERSEBYTES,
    OP_RIPEMD160: OP_RIPEMD160,
    OP_ROLL: OP_ROLL,
    OP_ROT: OP_ROT,
    OP_SHA1: OP_SHA1,
    OP_SHA256: OP_SHA256,
    OP_SIZE: OP_SIZE,
    OP_SPLIT: OP_SPLIT,
    OP_SUB: OP_SUB,
    OP_SWAP: OP_SWAP,
    OP_TOALTSTACK: OP_TOALTSTACK,
    OP_TRUE: OP_TRUE,
    OP_TUCK: OP_TUCK,
    OP_TXFIELD: OP_TXFIELD,
    OP_TXHASH: OP_TXHASH,
    OP_TXLOCKTIME: OP_TXLOCKTIME,
    OP_VERIFY: OP_VERIFY,
    OP_WITHIN: OP_WITHIN,
    OP_XNA_ASSET: OP_XNA_ASSET,
    TXFIELD_AUTHSCRIPT_COMMITMENT: TXFIELD_AUTHSCRIPT_COMMITMENT,
    TXFIELD_SCRIPTPUBKEY: TXFIELD_SCRIPTPUBKEY,
    TXFIELD_VALUE: TXFIELD_VALUE,
    TXHASH_ALL: TXHASH_ALL,
    TXHASH_CURRENT_INDEX: TXHASH_CURRENT_INDEX,
    TXHASH_CURRENT_PREVOUT: TXHASH_CURRENT_PREVOUT,
    TXHASH_CURRENT_SEQUENCE: TXHASH_CURRENT_SEQUENCE,
    TXHASH_INPUT_PREVOUTS: TXHASH_INPUT_PREVOUTS,
    TXHASH_INPUT_SEQUENCES: TXHASH_INPUT_SEQUENCES,
    TXHASH_LOCKTIME: TXHASH_LOCKTIME,
    TXHASH_OUTPUTS: TXHASH_OUTPUTS,
    TXHASH_VERSION: TXHASH_VERSION
});

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
function encodeScriptNum(value) {
    let n = typeof value === 'bigint' ? value : BigInt(value);
    if (n === 0n)
        return new Uint8Array();
    const negative = n < 0n;
    if (negative)
        n = -n;
    const result = [];
    while (n > 0n) {
        result.push(Number(n & 0xffn));
        n >>= 8n;
    }
    // If the most-significant bit is set, add a padding byte so the sign bit
    // is unambiguous. If negative, flip that sign bit instead.
    if (result[result.length - 1] & 0x80) {
        result.push(negative ? 0x80 : 0x00);
    }
    else if (negative) {
        result[result.length - 1] |= 0x80;
    }
    return Uint8Array.from(result);
}
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
function pushBytes(data) {
    if (data.length === 0) {
        return Uint8Array.of(OP_0);
    }
    if (data.length <= 75) {
        return concatBytes(Uint8Array.of(data.length), data);
    }
    if (data.length <= 0xff) {
        return concatBytes(Uint8Array.of(0x4c, data.length), data);
    }
    if (data.length <= 3072) {
        return concatBytes(Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff), data);
    }
    throw new Error(`pushBytes: element of ${data.length} bytes exceeds MAX_PQ_SCRIPT_ELEMENT_SIZE (3072)`);
}
/**
 * Emit a minimally-encoded integer push. Uses OP_1NEGATE, OP_0 and OP_1..OP_16
 * when available to match how the node's own templates look on the wire.
 */
function pushInt(value) {
    const n = typeof value === 'bigint' ? value : BigInt(value);
    if (n === -1n)
        return Uint8Array.of(OP_1NEGATE);
    if (n === 0n)
        return Uint8Array.of(OP_0);
    if (n >= 1n && n <= 16n) {
        return Uint8Array.of(OP_1 + Number(n) - 1);
    }
    return pushBytes(encodeScriptNum(n));
}
function pushHex(hex) {
    return pushBytes(hexToBytes(hex));
}
/** Fluent assembler for readable script definitions. */
class ScriptBuilder {
    parts = [];
    op(...opcodes) {
        for (const op of opcodes) {
            if (!Number.isInteger(op) || op < 0 || op > 0xff) {
                throw new Error(`Invalid opcode byte: ${op}`);
            }
            this.parts.push(Uint8Array.of(op));
        }
        return this;
    }
    pushInt(value) {
        this.parts.push(pushInt(value));
        return this;
    }
    pushBytes(data) {
        this.parts.push(pushBytes(data));
        return this;
    }
    pushHex(hex) {
        this.parts.push(pushHex(hex));
        return this;
    }
    raw(bytes) {
        this.parts.push(bytes);
        return this;
    }
    build() {
        return concatBytes(...this.parts);
    }
    buildHex() {
        return bytesToHex(this.build());
    }
}

/**
 * Pay-to-Public-Key-Hash (P2PKH) scriptPubKey.
 * Layout: OP_DUP OP_HASH160 0x14 <20-byte PKH> OP_EQUALVERIFY OP_CHECKSIG
 */
function encodeP2PKHScriptPubKey(pubKeyHash) {
    if (!(pubKeyHash instanceof Uint8Array) || pubKeyHash.length !== 20) {
        throw new Error('P2PKH pubKeyHash must be a 20-byte Uint8Array');
    }
    return concatBytes(Uint8Array.of(OP_DUP, OP_HASH160, 0x14), pubKeyHash, Uint8Array.of(OP_EQUALVERIFY, OP_CHECKSIG));
}

/**
 * Native segwit v0 Pay-to-Witness-Public-Key-Hash (P2WPKH) scriptPubKey.
 * Layout: OP_0 0x14 <20-byte HASH160(pubKey)>
 *
 * Callers compute HASH160 externally (e.g. via neurai-key / their crypto
 * stack). This helper only encodes the scriptPubKey once the hash is known.
 */
function encodeP2WPKHScriptPubKey(pubKeyHash) {
    if (!(pubKeyHash instanceof Uint8Array) || pubKeyHash.length !== 20) {
        throw new Error('P2WPKH pubKeyHash must be a 20-byte Uint8Array');
    }
    return concatBytes(Uint8Array.of(OP_0, 0x14), pubKeyHash);
}

/**
 * Native segwit v0 Pay-to-Witness-Script-Hash (P2WSH) scriptPubKey.
 * Layout: OP_0 0x20 <32-byte SHA256(witnessScript)>
 *
 * This helper takes the SHA256 digest of the witness script directly. The
 * SHA256 is computed externally by the caller's crypto stack (kept out of
 * this library to avoid a hash dependency).
 */
function encodeP2WSHScriptPubKey(witnessScriptSha256) {
    if (!(witnessScriptSha256 instanceof Uint8Array) || witnessScriptSha256.length !== 32) {
        throw new Error('P2WSH witnessScriptSha256 must be a 32-byte Uint8Array');
    }
    return concatBytes(Uint8Array.of(OP_0, 0x20), witnessScriptSha256);
}

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
const AUTHSCRIPT_NOAUTH = 0x00;
const AUTHSCRIPT_PQ = 0x01;
const AUTHSCRIPT_LEGACY = 0x02;
/** NIP-015: reference-script spend mode. Not yet activated in consensus. */
const AUTHSCRIPT_REF = 0x03;
/** Cap for PQ signature / pubkey pushes under NIP-018 (3072 B). */
const MAX_PQ_PUSH = 3072;
function encodeAuthScriptScriptPubKey(program) {
    if (!(program instanceof Uint8Array) || program.length !== 32) {
        throw new Error('AuthScript program must be a 32-byte Uint8Array');
    }
    return concatBytes(Uint8Array.of(OP_1, 0x20), program);
}
function assertWitnessScript(ws) {
    if (!(ws instanceof Uint8Array) || ws.length === 0) {
        throw new Error('witnessScript must be a non-empty Uint8Array');
    }
}
function assertArgs(args) {
    if (args == null)
        return;
    if (!Array.isArray(args)) {
        throw new Error('args must be an array of Uint8Array');
    }
    for (let i = 0; i < args.length; i += 1) {
        if (!(args[i] instanceof Uint8Array)) {
            throw new Error(`args[${i}] must be a Uint8Array`);
        }
    }
}
/**
 * Build the witness stack for a legacy ECDSA AuthScript spend.
 *
 * Returns an array of raw stack elements. Serialization of the witness
 * (compact-size item count + per-item length-prefixes) is the caller's
 * responsibility — neurai-create-transaction handles it at tx-assembly time.
 */
function buildAuthScriptWitnessLegacy(input) {
    if (!(input.signature instanceof Uint8Array) || input.signature.length === 0) {
        throw new Error('signature must be a non-empty Uint8Array');
    }
    if (!(input.pubKey instanceof Uint8Array) ||
        (input.pubKey.length !== 33 && input.pubKey.length !== 65)) {
        throw new Error('pubKey must be a compressed (33B) or uncompressed (65B) secp256k1 key');
    }
    assertArgs(input.args);
    assertWitnessScript(input.witnessScript);
    return [
        Uint8Array.of(AUTHSCRIPT_LEGACY),
        input.signature,
        input.pubKey,
        ...(input.args ?? []),
        input.witnessScript
    ];
}
/**
 * Build the witness stack for a PQ (ML-DSA-44) AuthScript spend.
 * NIP-018 must be active: both signature and pubKey are pushed as single
 * stack elements and may each be up to 3072 B.
 */
function buildAuthScriptWitnessPQ(input) {
    if (!(input.signature instanceof Uint8Array) || input.signature.length === 0) {
        throw new Error('signature must be a non-empty Uint8Array');
    }
    if (input.signature.length > MAX_PQ_PUSH) {
        throw new Error(`signature of ${input.signature.length} bytes exceeds MAX_PQ_SCRIPT_ELEMENT_SIZE (${MAX_PQ_PUSH})`);
    }
    if (!(input.pubKey instanceof Uint8Array) || input.pubKey.length === 0) {
        throw new Error('pubKey must be a non-empty Uint8Array');
    }
    if (input.pubKey.length > MAX_PQ_PUSH) {
        throw new Error(`pubKey of ${input.pubKey.length} bytes exceeds MAX_PQ_SCRIPT_ELEMENT_SIZE (${MAX_PQ_PUSH})`);
    }
    assertArgs(input.args);
    assertWitnessScript(input.witnessScript);
    return [
        Uint8Array.of(AUTHSCRIPT_PQ),
        input.signature,
        input.pubKey,
        ...(input.args ?? []),
        input.witnessScript
    ];
}
/**
 * Build the witness stack for a NoAuth AuthScript spend. The spend is gated
 * by the witnessScript alone (covenants, hash-locks, time-locks, ...); no
 * signature or public key is carried.
 */
function buildAuthScriptWitnessNoAuth(input) {
    assertArgs(input.args);
    assertWitnessScript(input.witnessScript);
    return [
        Uint8Array.of(AUTHSCRIPT_NOAUTH),
        ...(input.args ?? []),
        input.witnessScript
    ];
}
/**
 * Build the witness stack for a NIP-015 reference-script spend. The last
 * item is the 4-byte little-endian index into `tx.vrefin` that locates the
 * reference-script carrier output; the interpreter resolves the `refScript`
 * from that carrier at validation time.
 *
 * NOTE: NIP-015 is not yet activated in consensus. This builder emits the
 * spec-conformant witness for forward compatibility and testnet experiments.
 */
function buildAuthScriptWitnessRef(input) {
    if (!Number.isInteger(input.refIndex) || input.refIndex < 0 || input.refIndex > 0xffffffff) {
        throw new Error('refIndex must be a uint32 (0 .. 2^32 - 1)');
    }
    assertArgs(input.args);
    const refLocator = new Uint8Array(4);
    const dv = new DataView(refLocator.buffer);
    dv.setUint32(0, input.refIndex, /* little-endian */ true);
    return [
        Uint8Array.of(AUTHSCRIPT_REF),
        ...(input.args ?? []),
        refLocator
    ];
}

/**
 * Provably-unspendable OP_RETURN (null-data) output scripts.
 * Layout: OP_RETURN <push> [<push> ...]
 *
 * Neurai inherits the Bitcoin Core standard policy cap of 80 bytes of
 * payload for a relayed null-data output. Outputs over that cap are still
 * consensus-valid but will not be relayed by default mempool policy; use
 * the `allowNonStandard` option to opt in explicitly.
 */
const NULLDATA_STANDARD_MAX_SIZE = 80;
function encodeNullDataScript(payload, options = {}) {
    const payloads = payload instanceof Uint8Array ? [payload] : payload;
    if (!Array.isArray(payloads) || payloads.length === 0) {
        throw new Error('payload must be a Uint8Array or a non-empty array of Uint8Array');
    }
    let totalPayload = 0;
    for (let i = 0; i < payloads.length; i += 1) {
        const p = payloads[i];
        if (!(p instanceof Uint8Array)) {
            throw new Error(`payload[${i}] must be a Uint8Array`);
        }
        totalPayload += p.length;
    }
    if (!options.allowNonStandard && totalPayload > NULLDATA_STANDARD_MAX_SIZE) {
        throw new Error(`nulldata payload of ${totalPayload} bytes exceeds standard cap ${NULLDATA_STANDARD_MAX_SIZE}; set allowNonStandard=true to override`);
    }
    const parts = [Uint8Array.of(OP_RETURN)];
    for (const p of payloads)
        parts.push(pushBytes(p));
    return concatBytes(...parts);
}

/**
 * Classic bare m-of-n multisig via OP_CHECKMULTISIG, plus the P2SH wrapper
 * that is normally used in practice.
 *
 *   redeemScript = <m> <pubkey_1> ... <pubkey_n> <n> OP_CHECKMULTISIG
 *   P2SH spk     = OP_HASH160 0x14 <HASH160(redeemScript)> OP_EQUAL
 *
 * OP_CHECKMULTISIG caps n at 20 pubkeys (see `MAX_PUBKEYS_PER_MULTISIG` in
 * the Neurai interpreter). Bare multisig outputs are still consensus-valid
 * but non-standard for relay; the P2SH wrapping is what mempool accepts.
 */
const MULTISIG_MAX_PUBKEYS = 20;
function assertPubKey(pk, idx) {
    if (!(pk instanceof Uint8Array) || (pk.length !== 33 && pk.length !== 65)) {
        throw new Error(`pubKey[${idx}] must be 33 or 65 bytes (got ${pk?.length})`);
    }
}
function encodeMultisigRedeemScript({ m, pubKeys }) {
    if (!Array.isArray(pubKeys) || pubKeys.length === 0) {
        throw new Error('pubKeys must be a non-empty array');
    }
    if (pubKeys.length > MULTISIG_MAX_PUBKEYS) {
        throw new Error(`pubKeys length ${pubKeys.length} exceeds OP_CHECKMULTISIG cap (${MULTISIG_MAX_PUBKEYS})`);
    }
    if (!Number.isInteger(m) || m < 1 || m > pubKeys.length) {
        throw new Error(`m must be an integer in [1, ${pubKeys.length}] (got ${m})`);
    }
    for (let i = 0; i < pubKeys.length; i += 1)
        assertPubKey(pubKeys[i], i);
    const parts = [pushInt(m)];
    for (const pk of pubKeys)
        parts.push(pushBytes(pk));
    parts.push(pushInt(pubKeys.length));
    parts.push(Uint8Array.of(OP_CHECKMULTISIG));
    return concatBytes(...parts);
}
function encodeMultisigRedeemScriptHex(params) {
    return bytesToHex(encodeMultisigRedeemScript(params));
}
/**
 * P2SH scriptPubKey wrapping any redeem script. Pass the 20-byte HASH160 of
 * the redeem script (RIPEMD160(SHA256(redeemScript))) — compute it
 * externally via the caller's crypto stack.
 */
function encodeP2SHScriptPubKey(redeemScriptHash160) {
    if (!(redeemScriptHash160 instanceof Uint8Array) || redeemScriptHash160.length !== 20) {
        throw new Error('redeemScriptHash160 must be a 20-byte Uint8Array');
    }
    return concatBytes(Uint8Array.of(OP_HASH160, 0x14), redeemScriptHash160, Uint8Array.of(OP_EQUAL));
}

// base-x encoding / decoding
// Copyright (c) 2018 base-x contributors
// Copyright (c) 2014-2018 The Bitcoin Core developers (base58.cpp)
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
function base (ALPHABET) {
  if (ALPHABET.length >= 255) { throw new TypeError('Alphabet too long') }
  const BASE_MAP = new Uint8Array(256);
  for (let j = 0; j < BASE_MAP.length; j++) {
    BASE_MAP[j] = 255;
  }
  for (let i = 0; i < ALPHABET.length; i++) {
    const x = ALPHABET.charAt(i);
    const xc = x.charCodeAt(0);
    if (BASE_MAP[xc] !== 255) { throw new TypeError(x + ' is ambiguous') }
    BASE_MAP[xc] = i;
  }
  const BASE = ALPHABET.length;
  const LEADER = ALPHABET.charAt(0);
  const FACTOR = Math.log(BASE) / Math.log(256); // log(BASE) / log(256), rounded up
  const iFACTOR = Math.log(256) / Math.log(BASE); // log(256) / log(BASE), rounded up
  function encode (source) {
    // eslint-disable-next-line no-empty
    if (source instanceof Uint8Array) ; else if (ArrayBuffer.isView(source)) {
      source = new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
    } else if (Array.isArray(source)) {
      source = Uint8Array.from(source);
    }
    if (!(source instanceof Uint8Array)) { throw new TypeError('Expected Uint8Array') }
    if (source.length === 0) { return '' }
    // Skip & count leading zeroes.
    let zeroes = 0;
    let length = 0;
    let pbegin = 0;
    const pend = source.length;
    while (pbegin !== pend && source[pbegin] === 0) {
      pbegin++;
      zeroes++;
    }
    // Allocate enough space in big-endian base58 representation.
    const size = ((pend - pbegin) * iFACTOR + 1) >>> 0;
    const b58 = new Uint8Array(size);
    // Process the bytes.
    while (pbegin !== pend) {
      let carry = source[pbegin];
      // Apply "b58 = b58 * 256 + ch".
      let i = 0;
      for (let it1 = size - 1; (carry !== 0 || i < length) && (it1 !== -1); it1--, i++) {
        carry += (256 * b58[it1]) >>> 0;
        b58[it1] = (carry % BASE) >>> 0;
        carry = (carry / BASE) >>> 0;
      }
      if (carry !== 0) { throw new Error('Non-zero carry') }
      length = i;
      pbegin++;
    }
    // Skip leading zeroes in base58 result.
    let it2 = size - length;
    while (it2 !== size && b58[it2] === 0) {
      it2++;
    }
    // Translate the result into a string.
    let str = LEADER.repeat(zeroes);
    for (; it2 < size; ++it2) { str += ALPHABET.charAt(b58[it2]); }
    return str
  }
  function decodeUnsafe (source) {
    if (typeof source !== 'string') { throw new TypeError('Expected String') }
    if (source.length === 0) { return new Uint8Array() }
    let psz = 0;
    // Skip and count leading '1's.
    let zeroes = 0;
    let length = 0;
    while (source[psz] === LEADER) {
      zeroes++;
      psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    const size = (((source.length - psz) * FACTOR) + 1) >>> 0; // log(58) / log(256), rounded up.
    const b256 = new Uint8Array(size);
    // Process the characters.
    while (psz < source.length) {
      // Find code of next character
      const charCode = source.charCodeAt(psz);
      // Base map can not be indexed using char code
      if (charCode > 255) { return }
      // Decode character
      let carry = BASE_MAP[charCode];
      // Invalid character
      if (carry === 255) { return }
      let i = 0;
      for (let it3 = size - 1; (carry !== 0 || i < length) && (it3 !== -1); it3--, i++) {
        carry += (BASE * b256[it3]) >>> 0;
        b256[it3] = (carry % 256) >>> 0;
        carry = (carry / 256) >>> 0;
      }
      if (carry !== 0) { throw new Error('Non-zero carry') }
      length = i;
      psz++;
    }
    // Skip leading zeroes in b256.
    let it4 = size - length;
    while (it4 !== size && b256[it4] === 0) {
      it4++;
    }
    const vch = new Uint8Array(zeroes + (size - it4));
    let j = zeroes;
    while (it4 !== size) {
      vch[j++] = b256[it4++];
    }
    return vch
  }
  function decode (string) {
    const buffer = decodeUnsafe(string);
    if (buffer) { return buffer }
    throw new Error('Non-base' + BASE + ' character')
  }
  return {
    encode,
    decodeUnsafe,
    decode
  }
}

var ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
var base58 = base(ALPHABET);

var dist = {};

var hasRequiredDist;

function requireDist () {
	if (hasRequiredDist) return dist;
	hasRequiredDist = 1;
	Object.defineProperty(dist, "__esModule", { value: true });
	dist.bech32m = dist.bech32 = void 0;
	const ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
	const ALPHABET_MAP = {};
	for (let z = 0; z < ALPHABET.length; z++) {
	    const x = ALPHABET.charAt(z);
	    ALPHABET_MAP[x] = z;
	}
	function polymodStep(pre) {
	    const b = pre >> 25;
	    return (((pre & 0x1ffffff) << 5) ^
	        (-((b >> 0) & 1) & 0x3b6a57b2) ^
	        (-((b >> 1) & 1) & 0x26508e6d) ^
	        (-((b >> 2) & 1) & 0x1ea119fa) ^
	        (-((b >> 3) & 1) & 0x3d4233dd) ^
	        (-((b >> 4) & 1) & 0x2a1462b3));
	}
	function prefixChk(prefix) {
	    let chk = 1;
	    for (let i = 0; i < prefix.length; ++i) {
	        const c = prefix.charCodeAt(i);
	        if (c < 33 || c > 126)
	            return 'Invalid prefix (' + prefix + ')';
	        chk = polymodStep(chk) ^ (c >> 5);
	    }
	    chk = polymodStep(chk);
	    for (let i = 0; i < prefix.length; ++i) {
	        const v = prefix.charCodeAt(i);
	        chk = polymodStep(chk) ^ (v & 0x1f);
	    }
	    return chk;
	}
	function convert(data, inBits, outBits, pad) {
	    let value = 0;
	    let bits = 0;
	    const maxV = (1 << outBits) - 1;
	    const result = [];
	    for (let i = 0; i < data.length; ++i) {
	        value = (value << inBits) | data[i];
	        bits += inBits;
	        while (bits >= outBits) {
	            bits -= outBits;
	            result.push((value >> bits) & maxV);
	        }
	    }
	    if (pad) {
	        if (bits > 0) {
	            result.push((value << (outBits - bits)) & maxV);
	        }
	    }
	    else {
	        if (bits >= inBits)
	            return 'Excess padding';
	        if ((value << (outBits - bits)) & maxV)
	            return 'Non-zero padding';
	    }
	    return result;
	}
	function toWords(bytes) {
	    return convert(bytes, 8, 5, true);
	}
	function fromWordsUnsafe(words) {
	    const res = convert(words, 5, 8, false);
	    if (Array.isArray(res))
	        return res;
	}
	function fromWords(words) {
	    const res = convert(words, 5, 8, false);
	    if (Array.isArray(res))
	        return res;
	    throw new Error(res);
	}
	function getLibraryFromEncoding(encoding) {
	    let ENCODING_CONST;
	    if (encoding === 'bech32') {
	        ENCODING_CONST = 1;
	    }
	    else {
	        ENCODING_CONST = 0x2bc830a3;
	    }
	    function encode(prefix, words, LIMIT) {
	        LIMIT = LIMIT || 90;
	        if (prefix.length + 7 + words.length > LIMIT)
	            throw new TypeError('Exceeds length limit');
	        prefix = prefix.toLowerCase();
	        // determine chk mod
	        let chk = prefixChk(prefix);
	        if (typeof chk === 'string')
	            throw new Error(chk);
	        let result = prefix + '1';
	        for (let i = 0; i < words.length; ++i) {
	            const x = words[i];
	            if (x >> 5 !== 0)
	                throw new Error('Non 5-bit word');
	            chk = polymodStep(chk) ^ x;
	            result += ALPHABET.charAt(x);
	        }
	        for (let i = 0; i < 6; ++i) {
	            chk = polymodStep(chk);
	        }
	        chk ^= ENCODING_CONST;
	        for (let i = 0; i < 6; ++i) {
	            const v = (chk >> ((5 - i) * 5)) & 0x1f;
	            result += ALPHABET.charAt(v);
	        }
	        return result;
	    }
	    function __decode(str, LIMIT) {
	        LIMIT = LIMIT || 90;
	        if (str.length < 8)
	            return str + ' too short';
	        if (str.length > LIMIT)
	            return 'Exceeds length limit';
	        // don't allow mixed case
	        const lowered = str.toLowerCase();
	        const uppered = str.toUpperCase();
	        if (str !== lowered && str !== uppered)
	            return 'Mixed-case string ' + str;
	        str = lowered;
	        const split = str.lastIndexOf('1');
	        if (split === -1)
	            return 'No separator character for ' + str;
	        if (split === 0)
	            return 'Missing prefix for ' + str;
	        const prefix = str.slice(0, split);
	        const wordChars = str.slice(split + 1);
	        if (wordChars.length < 6)
	            return 'Data too short';
	        let chk = prefixChk(prefix);
	        if (typeof chk === 'string')
	            return chk;
	        const words = [];
	        for (let i = 0; i < wordChars.length; ++i) {
	            const c = wordChars.charAt(i);
	            const v = ALPHABET_MAP[c];
	            if (v === undefined)
	                return 'Unknown character ' + c;
	            chk = polymodStep(chk) ^ v;
	            // not in the checksum?
	            if (i + 6 >= wordChars.length)
	                continue;
	            words.push(v);
	        }
	        if (chk !== ENCODING_CONST)
	            return 'Invalid checksum for ' + str;
	        return { prefix, words };
	    }
	    function decodeUnsafe(str, LIMIT) {
	        const res = __decode(str, LIMIT);
	        if (typeof res === 'object')
	            return res;
	    }
	    function decode(str, LIMIT) {
	        const res = __decode(str, LIMIT);
	        if (typeof res === 'object')
	            return res;
	        throw new Error(res);
	    }
	    return {
	        decodeUnsafe,
	        decode,
	        encode,
	        toWords,
	        fromWordsUnsafe,
	        fromWords,
	    };
	}
	dist.bech32 = getLibraryFromEncoding('bech32');
	dist.bech32m = getLibraryFromEncoding('bech32m');
	return dist;
}

var distExports = requireDist();

/**
 * Utilities for hex, bytes, CSPRNG.
 * @module
 */
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
// node.js versions earlier than v19 don't declare it in global scope.
// For node.js, package.json#exports field mapping rewrites import
// from `crypto` to `cryptoNode`, which imports native module.
// Makes the utils un-importable in browsers without a bundler.
// Once node.js 18 is deprecated (2025-04-30), we can just drop the import.
/** Checks if something is Uint8Array. Be careful: nodejs Buffer will return true. */
function isBytes(a) {
    return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
}
/** Asserts something is Uint8Array. */
function abytes(b, ...lengths) {
    if (!isBytes(b))
        throw new Error('Uint8Array expected');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new Error('Uint8Array expected of length ' + lengths + ', got length=' + b.length);
}
/** Asserts a hash instance has not been destroyed / finished */
function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
/** Asserts output is properly-sized byte array */
function aoutput(out, instance) {
    abytes(out);
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error('digestInto() expects output buffer of length at least ' + min);
    }
}
/** Zeroize a byte array. Warning: JS provides no guarantees. */
function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
        arrays[i].fill(0);
    }
}
/** Create DataView of an array for easy byte-level manipulation. */
function createView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
/** The rotate right (circular right shift) operation for uint32 */
function rotr(word, shift) {
    return (word << (32 - shift)) | (word >>> shift);
}
/**
 * Converts string to bytes using UTF8 encoding.
 * @example utf8ToBytes('abc') // Uint8Array.from([97, 98, 99])
 */
function utf8ToBytes(str) {
    if (typeof str !== 'string')
        throw new Error('string expected');
    return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}
/**
 * Normalizes (non-hex) string or Uint8Array to Uint8Array.
 * Warning: when Uint8Array is passed, it would NOT get copied.
 * Keep in mind for future mutable operations.
 */
function toBytes(data) {
    if (typeof data === 'string')
        data = utf8ToBytes(data);
    abytes(data);
    return data;
}
/** For runtime check if class implements interface */
class Hash {
}
/** Wraps hash function, creating an interface on top of it */
function createHasher(hashCons) {
    const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
    const tmp = hashCons();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashCons();
    return hashC;
}

/**
 * Internal Merkle-Damgard hash utils.
 * @module
 */
/** Polyfill for Safari 14. https://caniuse.com/mdn-javascript_builtins_dataview_setbiguint64 */
function setBigUint64(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === 'function')
        return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(0xffffffff);
    const wh = Number((value >> _32n) & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
}
/** Choice: a ? b : c */
function Chi(a, b, c) {
    return (a & b) ^ (~a & c);
}
/** Majority function, true if any two inputs is true. */
function Maj(a, b, c) {
    return (a & b) ^ (a & c) ^ (b & c);
}
/**
 * Merkle-Damgard hash construction base class.
 * Could be used to create MD5, RIPEMD, SHA1, SHA2.
 */
class HashMD extends Hash {
    constructor(blockLen, outputLen, padOffset, isLE) {
        super();
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE;
        this.buffer = new Uint8Array(blockLen);
        this.view = createView(this.buffer);
    }
    update(data) {
        aexists(this);
        data = toBytes(data);
        abytes(data);
        const { view, buffer, blockLen } = this;
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            // Fast path: we have at least one block in input, cast it to view and process
            if (take === blockLen) {
                const dataView = createView(data);
                for (; blockLen <= len - pos; pos += blockLen)
                    this.process(dataView, pos);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
                this.process(view, 0);
                this.pos = 0;
            }
        }
        this.length += data.length;
        this.roundClean();
        return this;
    }
    digestInto(out) {
        aexists(this);
        aoutput(out, this);
        this.finished = true;
        // Padding
        // We can avoid allocation of buffer for padding completely if it
        // was previously not allocated here. But it won't change performance.
        const { buffer, view, blockLen, isLE } = this;
        let { pos } = this;
        // append the bit '1' to the message
        buffer[pos++] = 0b10000000;
        clean(this.buffer.subarray(pos));
        // we have less than padOffset left in buffer, so we cannot put length in
        // current block, need process it and pad again
        if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
        }
        // Pad until full block byte with zeros
        for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
        // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
        // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
        // So we just write lowest 64 bits of that value.
        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
        this.process(view, 0);
        const oview = createView(out);
        const len = this.outputLen;
        // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
        if (len % 4)
            throw new Error('_sha2: outputLen should be aligned to 32bit');
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
            throw new Error('_sha2: outputLen bigger than state');
        for (let i = 0; i < outLen; i++)
            oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
    _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.destroyed = destroyed;
        to.finished = finished;
        to.length = length;
        to.pos = pos;
        if (length % blockLen)
            to.buffer.set(buffer);
        return to;
    }
    clone() {
        return this._cloneInto();
    }
}
/**
 * Initial SHA-2 state: fractional parts of square roots of first 16 primes 2..53.
 * Check out `test/misc/sha2-gen-iv.js` for recomputation guide.
 */
/** Initial SHA256 state. Bits 0..32 of frac part of sqrt of primes 2..19 */
const SHA256_IV = /* @__PURE__ */ Uint32Array.from([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

/**
 * SHA2 hash function. A.k.a. sha256, sha384, sha512, sha512_224, sha512_256.
 * SHA256 is the fastest hash implementable in JS, even faster than Blake3.
 * Check out [RFC 4634](https://datatracker.ietf.org/doc/html/rfc4634) and
 * [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
 * @module
 */
/**
 * Round constants:
 * First 32 bits of fractional parts of the cube roots of the first 64 primes 2..311)
 */
// prettier-ignore
const SHA256_K = /* @__PURE__ */ Uint32Array.from([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
/** Reusable temporary buffer. "W" comes straight from spec. */
const SHA256_W = /* @__PURE__ */ new Uint32Array(64);
class SHA256 extends HashMD {
    constructor(outputLen = 32) {
        super(64, outputLen, 8, false);
        // We cannot use array here since array allows indexing by variable
        // which means optimizer/compiler cannot use registers.
        this.A = SHA256_IV[0] | 0;
        this.B = SHA256_IV[1] | 0;
        this.C = SHA256_IV[2] | 0;
        this.D = SHA256_IV[3] | 0;
        this.E = SHA256_IV[4] | 0;
        this.F = SHA256_IV[5] | 0;
        this.G = SHA256_IV[6] | 0;
        this.H = SHA256_IV[7] | 0;
    }
    get() {
        const { A, B, C, D, E, F, G, H } = this;
        return [A, B, C, D, E, F, G, H];
    }
    // prettier-ignore
    set(A, B, C, D, E, F, G, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G | 0;
        this.H = H | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W[i - 15];
            const W2 = SHA256_W[i - 2];
            const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3);
            const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10);
            SHA256_W[i] = (s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16]) | 0;
        }
        // Compression function main loop, 64 rounds
        let { A, B, C, D, E, F, G, H } = this;
        for (let i = 0; i < 64; i++) {
            const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
            const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
            const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
            const T2 = (sigma0 + Maj(A, B, C)) | 0;
            H = G;
            G = F;
            F = E;
            E = (D + T1) | 0;
            D = C;
            C = B;
            B = A;
            A = (T1 + T2) | 0;
        }
        // Add the compressed chunk to the current hash value
        A = (A + this.A) | 0;
        B = (B + this.B) | 0;
        C = (C + this.C) | 0;
        D = (D + this.D) | 0;
        E = (E + this.E) | 0;
        F = (F + this.F) | 0;
        G = (G + this.G) | 0;
        H = (H + this.H) | 0;
        this.set(A, B, C, D, E, F, G, H);
    }
    roundClean() {
        clean(SHA256_W);
    }
    destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        clean(this.buffer);
    }
}
/**
 * SHA2-256 hash function from RFC 4634.
 *
 * It is the fastest JS hash, even faster than Blake3.
 * To break sha256 using birthday attack, attackers need to try 2^128 hashes.
 * BTC network is doing 2^70 hashes/sec (2^95 hashes/year) as per 2025.
 */
const sha256$1 = /* @__PURE__ */ createHasher(() => new SHA256());

/**
 * SHA2-256 a.k.a. sha256. In JS, it is the fastest hash, even faster than Blake3.
 *
 * To break sha256 using birthday attack, attackers need to try 2^128 hashes.
 * BTC network is doing 2^70 hashes/sec (2^95 hashes/year) as per 2025.
 *
 * Check out [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
 * @module
 * @deprecated
 */
/** @deprecated Use import from `noble/hashes/sha2` module */
const sha256 = sha256$1;

function bs58checkBase (checksumFn) {
    // Encode a buffer as a base58-check encoded string
    function encode(payload) {
        var payloadU8 = Uint8Array.from(payload);
        var checksum = checksumFn(payloadU8);
        var length = payloadU8.length + 4;
        var both = new Uint8Array(length);
        both.set(payloadU8, 0);
        both.set(checksum.subarray(0, 4), payloadU8.length);
        return base58.encode(both);
    }
    function decodeRaw(buffer) {
        var payload = buffer.slice(0, -4);
        var checksum = buffer.slice(-4);
        var newChecksum = checksumFn(payload);
        // eslint-disable-next-line
        if (checksum[0] ^ newChecksum[0] |
            checksum[1] ^ newChecksum[1] |
            checksum[2] ^ newChecksum[2] |
            checksum[3] ^ newChecksum[3])
            return;
        return payload;
    }
    // Decode a base58-check encoded string to a buffer, no result if checksum is wrong
    function decodeUnsafe(str) {
        var buffer = base58.decodeUnsafe(str);
        if (buffer == null)
            return;
        return decodeRaw(buffer);
    }
    function decode(str) {
        var buffer = base58.decode(str);
        var payload = decodeRaw(buffer);
        if (payload == null)
            throw new Error('Invalid checksum');
        return payload;
    }
    return {
        encode: encode,
        decode: decode,
        decodeUnsafe: decodeUnsafe
    };
}

// SHA256(SHA256(buffer))
function sha256x2(buffer) {
    return sha256(sha256(buffer));
}
var bs58check = bs58checkBase(sha256x2);

function resolveAddressInput(address) {
    if (typeof address === 'string') {
        return String(address).trim();
    }
    if (address && typeof address.address === 'string') {
        return String(address.address).trim();
    }
    throw new Error('Address must be a string or an object with an address field');
}

const LEGACY_MAINNET_PREFIX = 53;
const LEGACY_TESTNET_PREFIX = 127;
const PQ_MAINNET_HRP = 'nq';
const PQ_TESTNET_HRP = 'tnq';
function inferNetworkFromAddress(address) {
    const normalized = resolveAddressInput(address).toLowerCase();
    if (normalized.startsWith(PQ_MAINNET_HRP + '1'))
        return 'xna-pq';
    if (normalized.startsWith(PQ_TESTNET_HRP + '1'))
        return 'xna-pq-test';
    if (normalized.startsWith('n'))
        return 'xna';
    if (normalized.startsWith('t'))
        return 'xna-test';
    throw new Error(`Unsupported Neurai address: ${address}`);
}

function decodeAddress(address) {
    const normalized = resolveAddressInput(address);
    const lowered = normalized.toLowerCase();
    if (!normalized)
        throw new Error('Address is required');
    if (lowered.startsWith(PQ_MAINNET_HRP + '1') || lowered.startsWith(PQ_TESTNET_HRP + '1')) {
        const decoded = distExports.bech32m.decode(normalized);
        const version = decoded.words[0];
        const program = Uint8Array.from(distExports.bech32m.fromWords(decoded.words.slice(1)));
        if (version !== 1 || program.length !== 32) {
            throw new Error(`Unsupported AuthScript address program for ${address}`);
        }
        const network = lowered.startsWith(PQ_TESTNET_HRP + '1') ? 'xna-pq-test' : 'xna-pq';
        return { address: normalized, type: 'authscript', network, program, commitment: program };
    }
    const payload = Uint8Array.from(bs58check.decode(normalized));
    if (payload.length !== 21) {
        throw new Error(`Unsupported legacy address payload length for ${address}`);
    }
    const prefix = payload[0];
    if (prefix !== LEGACY_MAINNET_PREFIX && prefix !== LEGACY_TESTNET_PREFIX) {
        throw new Error(`Unsupported legacy address prefix ${prefix} for ${address}`);
    }
    return {
        address: normalized,
        type: 'p2pkh',
        network: inferNetworkFromAddress(normalized),
        program: payload.slice(1),
        hash: payload.slice(1)
    };
}

/**
 * Address helpers. Wraps `decodeAddress` from
 * `@neuraiproject/neurai-create-transaction` to produce the exact
 * scriptPubKey bytes a covenant needs to hardcode. The actual
 * scriptPubKey encoders live in `./standard/*`; this module delegates.
 *
 * Two destination types are supported for the payment output (output[0]):
 *   - Legacy P2PKH (base58check)
 *   - AuthScript witness v1 (bech32m)
 */
/**
 * Resolve any accepted seller address string into its scriptPubKey.
 * The returned bytes are what the covenant will hardcode and later verify
 * via `OP_OUTPUTSCRIPT == <bytes>`.
 */
function encodeSellerScriptPubKey(address) {
    const decoded = decodeAddress(address);
    if (decoded.type === 'p2pkh') {
        const hash = Uint8Array.from(decoded.hash);
        return {
            kind: 'p2pkh',
            bytes: encodeP2PKHScriptPubKey(hash),
            hash
        };
    }
    if (decoded.type === 'authscript') {
        const program = Uint8Array.from(decoded.program);
        return {
            kind: 'authscript',
            bytes: encodeAuthScriptScriptPubKey(program),
            hash: program
        };
    }
    throw new Error(`Unsupported seller address type for "${address}"`);
}

/**
 * Asset-transfer wrapper split helper.
 *
 * Neurai asset UTXOs have a scriptPubKey of the form
 *
 *     <prefix scriptPubKey bytes> OP_XNA_ASSET <pushdata(payload)> OP_DROP
 *
 * where `prefix` is the recipient's standard script (typically a P2PKH, an
 * AuthScript witness v1, or a bare covenant such as the partial-fill sell
 * order), and `payload` serializes a `CAssetTransfer`:
 *
 *     payload = rvn_prefix (0x72 0x76 0x6e) || type_marker (0x74 transfer)
 *             || VarStr(assetName)
 *             || int64LE(amountRaw)
 *             [ || messageRef (optional) || int64LE(expireTime) (optional) ]
 *
 * This helper separates the two halves so consumers can validate the prefix
 * (e.g. feed it to `parsePartialFillScript`) while independently reading the
 * asset data displayed to the user. The optional payload tail
 * (`message` + `expireTime`) is tolerated but not exposed — the first
 * version only needs `assetName` and `amountRaw`.
 *
 * Bare (non-wrapped) scriptPubKeys round-trip through this helper by
 * returning `prefixHex === input` and `assetTransfer === null`.
 */
const RVN_MAGIC = Uint8Array.from([0x72, 0x76, 0x6e]); // "rvn"
const TRANSFER_TYPE = 0x74;
/**
 * Walk the script one opcode at a time, skipping pushdata payload bytes,
 * until either OP_XNA_ASSET is reached at top level or the end of the
 * script. Returns the byte offset of OP_XNA_ASSET, or -1 if not found.
 * Throws on truncated pushdata.
 */
function findTopLevelAssetOpcode(bytes) {
    let i = 0;
    while (i < bytes.length) {
        const op = bytes[i];
        if (op === OP_XNA_ASSET)
            return i;
        // Short direct push: 0x01..0x4b
        if (op >= 0x01 && op <= 0x4b) {
            const len = op;
            const next = i + 1 + len;
            if (next > bytes.length) {
                throw new Error(`splitAssetWrappedScriptPubKey: short push of ${len} bytes at offset ${i} exceeds script length`);
            }
            i = next;
            continue;
        }
        if (op === OP_PUSHDATA1) {
            if (i + 1 >= bytes.length) {
                throw new Error(`splitAssetWrappedScriptPubKey: truncated PUSHDATA1 length at offset ${i}`);
            }
            const len = bytes[i + 1];
            const next = i + 2 + len;
            if (next > bytes.length) {
                throw new Error(`splitAssetWrappedScriptPubKey: PUSHDATA1 of ${len} bytes at offset ${i} exceeds script length`);
            }
            i = next;
            continue;
        }
        if (op === OP_PUSHDATA2) {
            if (i + 2 >= bytes.length) {
                throw new Error(`splitAssetWrappedScriptPubKey: truncated PUSHDATA2 length at offset ${i}`);
            }
            const len = bytes[i + 1] | (bytes[i + 2] << 8);
            const next = i + 3 + len;
            if (next > bytes.length) {
                throw new Error(`splitAssetWrappedScriptPubKey: PUSHDATA2 of ${len} bytes at offset ${i} exceeds script length`);
            }
            i = next;
            continue;
        }
        if (op === OP_PUSHDATA4) {
            if (i + 4 >= bytes.length) {
                throw new Error(`splitAssetWrappedScriptPubKey: truncated PUSHDATA4 length at offset ${i}`);
            }
            const len = (bytes[i + 1] |
                (bytes[i + 2] << 8) |
                (bytes[i + 3] << 16) |
                (bytes[i + 4] << 24)) >>>
                0;
            const next = i + 5 + len;
            if (next > bytes.length) {
                throw new Error(`splitAssetWrappedScriptPubKey: PUSHDATA4 of ${len} bytes at offset ${i} exceeds script length`);
            }
            i = next;
            continue;
        }
        // Any other opcode (including OP_1..OP_16, OP_DUP, OP_HASH160, etc.) is
        // one byte wide in Neurai Script. Advance.
        i += 1;
    }
    return -1;
}
/**
 * Read the pushdata element that sits immediately after OP_XNA_ASSET and
 * return its payload bytes together with the cursor position after the
 * element. Only direct pushes (1..75) and PUSHDATA1 are accepted — a
 * well-formed asset transfer payload fits within 75 bytes for the common
 * case and comfortably within 255 bytes even with long names and tails.
 * PUSHDATA2 and PUSHDATA4 would signal a malformed or adversarial wrapper.
 */
function readPayloadPush(bytes, start) {
    if (start >= bytes.length) {
        throw new Error('splitAssetWrappedScriptPubKey: truncated wrapper — missing payload push');
    }
    const op = bytes[start];
    if (op >= 0x01 && op <= 0x4b) {
        const len = op;
        const dataStart = start + 1;
        const dataEnd = dataStart + len;
        if (dataEnd > bytes.length) {
            throw new Error(`splitAssetWrappedScriptPubKey: asset payload short push of ${len} bytes exceeds script length`);
        }
        return { payload: bytes.slice(dataStart, dataEnd), after: dataEnd };
    }
    if (op === OP_PUSHDATA1) {
        if (start + 1 >= bytes.length) {
            throw new Error('splitAssetWrappedScriptPubKey: truncated PUSHDATA1 in asset payload');
        }
        const len = bytes[start + 1];
        const dataStart = start + 2;
        const dataEnd = dataStart + len;
        if (dataEnd > bytes.length) {
            throw new Error(`splitAssetWrappedScriptPubKey: asset payload PUSHDATA1 of ${len} bytes exceeds script length`);
        }
        return { payload: bytes.slice(dataStart, dataEnd), after: dataEnd };
    }
    throw new Error(`splitAssetWrappedScriptPubKey: asset payload push opcode 0x${op.toString(16)} not accepted (expected 0x01..0x4b or PUSHDATA1)`);
}
function parseAssetTransferPayload(payload) {
    if (payload.length < 4 + 1 + 8) {
        // 4 magic+type, 1 varstr length, 8 int64LE amount
        throw new Error(`splitAssetWrappedScriptPubKey: asset payload of ${payload.length} bytes is too short`);
    }
    for (let i = 0; i < 3; i += 1) {
        if (payload[i] !== RVN_MAGIC[i]) {
            throw new Error(`splitAssetWrappedScriptPubKey: asset payload magic mismatch — expected "rvn" got 0x${payload[0].toString(16)} 0x${payload[1].toString(16)} 0x${payload[2].toString(16)}`);
        }
    }
    if (payload[3] !== TRANSFER_TYPE) {
        throw new Error(`splitAssetWrappedScriptPubKey: asset payload type marker 0x${payload[3].toString(16)} is not a transfer (0x74)`);
    }
    const nameLen = payload[4];
    const nameStart = 5;
    const nameEnd = nameStart + nameLen;
    if (nameEnd + 8 > payload.length) {
        throw new Error(`splitAssetWrappedScriptPubKey: asset payload truncated — name length ${nameLen} does not leave room for amount`);
    }
    let assetName = '';
    for (let i = nameStart; i < nameEnd; i += 1) {
        assetName += String.fromCharCode(payload[i]);
    }
    let amountRaw = 0n;
    for (let i = 0; i < 8; i += 1) {
        amountRaw |= BigInt(payload[nameEnd + i]) << BigInt(8 * i);
    }
    // Any bytes after nameEnd + 8 form the optional tail (message +
    // expireTime). We intentionally ignore them in this first version; the
    // raw payload remains available via `payloadHex` if a consumer later
    // needs to inspect them.
    return { assetName, amountRaw };
}
/**
 * Parse an asset-transfer-wrapped scriptPubKey. Accepts both wrapped and
 * bare forms. Throws on structural malformation (truncated pushdata,
 * missing OP_DROP after payload, bad magic, unsupported pushdata width).
 */
function splitAssetWrappedScriptPubKey(spkHex) {
    const normalized = ensureHex(spkHex, 'scriptPubKey');
    const bytes = hexToBytes(normalized);
    const assetOpAt = findTopLevelAssetOpcode(bytes);
    if (assetOpAt < 0) {
        return { prefixHex: normalized, assetTransfer: null };
    }
    const prefix = bytes.slice(0, assetOpAt);
    const { payload, after } = readPayloadPush(bytes, assetOpAt + 1);
    if (after >= bytes.length) {
        throw new Error('splitAssetWrappedScriptPubKey: asset wrapper missing trailing OP_DROP');
    }
    if (bytes[after] !== OP_DROP) {
        throw new Error(`splitAssetWrappedScriptPubKey: expected OP_DROP at offset ${after}, got 0x${bytes[after].toString(16)}`);
    }
    if (after + 1 !== bytes.length) {
        throw new Error(`splitAssetWrappedScriptPubKey: ${bytes.length - after - 1} trailing bytes after OP_DROP`);
    }
    const { assetName, amountRaw } = parseAssetTransferPayload(payload);
    return {
        prefixHex: bytesToHex(prefix),
        assetTransfer: {
            assetName,
            amountRaw,
            payloadHex: bytesToHex(payload),
        },
    };
}

/**
 * Partial-Fill Sell Order covenant script.
 *
 * The covenant has two branches selected by the top of the unlock stack:
 *
 *   OP_IF   (unlock pushed 1)  → Cancel: seller signs, recovers remainder.
 *   OP_ELSE (unlock pushed 0)  → Public partial fill: buyer provides the
 *                                 fill amount `N` and the tx layout is
 *                                 validated byte by byte.
 *
 * The partial-fill branch enforces a fixed output layout so that the script
 * stays compact and parseable:
 *
 *   output[0] = XNA payment to seller   (value >= N * unitPriceSats)
 *   output[1] = asset to buyer          (tokenId, amount == N)
 *   output[2] = covenant remainder      (same scriptPubKey, amount == in - N)
 *   output[3+] = optional buyer change  (not constrained by the covenant)
 *
 * The remainder UTXO reuses the spent scriptPubKey via
 * `OP_OUTPUTSCRIPT == OP_TXFIELD 0x03`, so the covenant is self-replicating
 * without hardcoding its own hash.
 *
 * The cancel branch uses classical ECDSA (`OP_HASH160 + OP_CHECKSIG`) and
 * commits to a 20-byte PKH. As a consequence this variant only accepts
 * legacy P2PKH addresses as the seller destination. For AuthScript bech32m
 * destinations and post-quantum signing, use `buildPartialFillScriptPQ`.
 */
const ASSET_NAME_MAX$1 = 32;
function decodeSellerAddress(sellerAddress) {
    if (typeof sellerAddress !== 'string' || sellerAddress.length === 0) {
        throw new Error('sellerAddress is required');
    }
    const decoded = decodeAddress(sellerAddress);
    if (decoded.type !== 'p2pkh') {
        throw new Error(`sellerAddress must be a legacy P2PKH address (the legacy partial-fill covenant uses OP_HASH160 + OP_CHECKSIG); ` +
            `got ${decoded.type}. Use buildPartialFillScriptPQ for AuthScript destinations.`);
    }
    const pkh = Uint8Array.from(decoded.hash);
    if (pkh.length !== 20) {
        throw new Error(`decoded sellerAddress produced a ${pkh.length}-byte hash, expected 20`);
    }
    return pkh;
}
function assertTokenId$1(tokenId) {
    if (typeof tokenId !== 'string' || tokenId.length === 0) {
        throw new Error('tokenId is required');
    }
    if (!/^[A-Z0-9._]+$/.test(tokenId)) {
        throw new Error(`tokenId "${tokenId}" is not a valid Neurai asset name`);
    }
    if (tokenId.length > ASSET_NAME_MAX$1) {
        throw new Error(`tokenId exceeds ${ASSET_NAME_MAX$1} bytes`);
    }
}
function assertPrice$1(priceSats) {
    if (typeof priceSats !== 'bigint') {
        throw new Error('unitPriceSats must be a bigint (satoshis per indivisible unit)');
    }
    if (priceSats <= 0n) {
        throw new Error('unitPriceSats must be > 0');
    }
    // 8-byte signed int ceiling: values beyond this cannot be produced by OP_MUL
    // inside the covenant without overflow (CScriptNum is int64).
    if (priceSats > 0x7fffffffffffffffn) {
        throw new Error('unitPriceSats exceeds int64 range');
    }
}
/**
 * Build the `scriptPubKey` of a Partial-Fill Sell Order covenant UTXO.
 * Returns raw bytes; wrap with `bytesToHex` for wire format.
 */
function buildPartialFillScript(params) {
    const { sellerAddress, tokenId, unitPriceSats } = params;
    const sellerPubKeyHash = decodeSellerAddress(sellerAddress);
    assertTokenId$1(tokenId);
    assertPrice$1(unitPriceSats);
    const sellerScriptPubKey = encodeP2PKHScriptPubKey(sellerPubKeyHash);
    const tokenIdBytes = new TextEncoder().encode(tokenId);
    const b = new ScriptBuilder();
    // ───────── Cancel branch (IF) ─────────
    // scriptSig expected: <sig> <pubkey> OP_1
    b.op(OP_IF)
        .op(OP_DUP, OP_HASH160)
        .pushBytes(sellerPubKeyHash)
        .op(OP_EQUALVERIFY, OP_CHECKSIG)
        .op(OP_ELSE);
    // ───────── Partial-fill branch (ELSE) ─────────
    // scriptSig expected: <N> OP_0
    //
    // Stack invariant entering the ELSE branch: [ N ]
    // 1. Payment value to seller (output 0)
    //    require outputValue(0) >= N * unitPriceSats
    b.op(OP_DUP) // [ N, N ]
        .pushInt(unitPriceSats) // [ N, N, price ]
        .op(OP_MUL) // [ N, N*price ]
        .pushInt(0) // [ N, N*price, 0 ]
        .op(OP_OUTPUTVALUE) // [ N, N*price, value ]
        .op(OP_SWAP) // [ N, value, N*price ]
        .op(OP_GREATERTHANOREQUAL)
        .op(OP_VERIFY); // [ N ]
    // 2. Payment scriptPubKey must equal Alice's (output 0)
    b.pushInt(0)
        .op(OP_OUTPUTSCRIPT) // [ N, scriptPubKey_out0 ]
        .pushBytes(sellerScriptPubKey)
        .op(OP_EQUALVERIFY); // [ N ]
    // 3. Asset delivered to buyer (output 1): amount == N
    b.op(OP_DUP) // [ N, N ]
        .pushInt(1) // [ N, N, 1 ]
        .pushInt(ASSETFIELD_AMOUNT)
        .op(OP_OUTPUTASSETFIELD) // [ N, N, amount_out1 ]
        .op(OP_EQUALVERIFY); // [ N ]
    // 4. Asset delivered to buyer (output 1): name == tokenId
    b.pushInt(1)
        .pushInt(ASSETFIELD_NAME)
        .op(OP_OUTPUTASSETFIELD) // [ N, name_out1 ]
        .pushBytes(tokenIdBytes)
        .op(OP_EQUALVERIFY); // [ N ]
    // 5. Remainder covenant continuity (output 2): same scriptPubKey as spent
    b.pushInt(2)
        .op(OP_OUTPUTSCRIPT) // [ N, spk_out2 ]
        .pushInt(TXFIELD_SCRIPTPUBKEY)
        .op(OP_TXFIELD) // [ N, spk_out2, spent_spk ]
        .op(OP_EQUALVERIFY); // [ N ]
    // 6. Remainder output: same tokenId
    b.pushInt(2)
        .pushInt(ASSETFIELD_NAME)
        .op(OP_OUTPUTASSETFIELD) // [ N, name_out2 ]
        .pushBytes(tokenIdBytes)
        .op(OP_EQUALVERIFY); // [ N ]
    // 7. Remainder output: amount == inputAssetAmount - N
    b.pushInt(2)
        .pushInt(ASSETFIELD_AMOUNT)
        .op(OP_OUTPUTASSETFIELD) // [ N, rem_amount ]
        .op(OP_OVER) // [ N, rem_amount, N ]       -- copy N under top
        .pushInt(0) // [ N, rem_amount, N, 0 ]
        .pushInt(ASSETFIELD_AMOUNT)
        .op(OP_INPUTASSETFIELD) // [ N, rem_amount, N, in_amount ]
        .op(OP_SWAP) // [ N, rem_amount, in_amount, N ]
        .op(OP_SUB) // [ N, rem_amount, in_amount - N ]
        .op(OP_EQUALVERIFY); // [ N ]
    // Drop N, leave TRUE on the stack so the ELSE branch evaluates as success.
    b.op(OP_DROP).pushInt(1);
    b.op(OP_ENDIF);
    return b.build();
}
/** Hex convenience wrapper for `buildPartialFillScript`. */
function buildPartialFillScriptHex(params) {
    return bytesToHex(buildPartialFillScript(params));
}

/**
 * PQ (post-quantum) variant of the Partial-Fill Sell Order covenant.
 *
 * Identical partial-fill branch to the legacy covenant, but the **cancel**
 * branch accepts an ML-DSA-44 signature instead of an ECDSA one. This
 * requires:
 *   - `SCRIPT_VERIFY_CHECKSIGFROMSTACK` (for OP_CSFS) active
 *   - `SCRIPT_VERIFY_TXHASH` (for OP_TXHASH) active
 *   - NIP-18 (`MAX_PQ_SCRIPT_ELEMENT_SIZE = 3072`) active, so the ~2.4 KB
 *     signature and ~1.3 KB pubkey can be pushed to the script stack
 *
 * All three are active on DePIN-Test testnet.
 *
 * Cancel-branch flow (scriptSig pushes `<sig> <pubkey> OP_1`):
 *
 *   1. OP_DUP OP_SHA256 <commitment> OP_EQUALVERIFY   → pubkey matches
 *   2. <selector> OP_TXHASH                           → message = H(tx)
 *   3. OP_SWAP OP_CHECKSIGFROMSTACK                   → CSFS verifies sig
 *
 * The message that gets signed is **SHA256(OP_TXHASH(selector))** — CSFS
 * single-SHA256s its message argument before verification, and OP_TXHASH
 * produces its own 32-byte hash, so the seller computes:
 *   `sign(pqSeckey, SHA256(doubleSHA256(selected_tx_fields)))`
 */
const ASSET_NAME_MAX = 32;
const DEFAULT_PQ_TXHASH_SELECTOR = 0xff;
function assertCommitment(commitment) {
    if (!(commitment instanceof Uint8Array) || commitment.length !== 32) {
        throw new Error('pubKeyCommitment must be a 32-byte Uint8Array (SHA256 of pubKey)');
    }
}
function assertTokenId(tokenId) {
    if (typeof tokenId !== 'string' || tokenId.length === 0) {
        throw new Error('tokenId is required');
    }
    if (!/^[A-Z0-9._]+$/.test(tokenId)) {
        throw new Error(`tokenId "${tokenId}" is not a valid Neurai asset name`);
    }
    if (tokenId.length > ASSET_NAME_MAX) {
        throw new Error(`tokenId exceeds ${ASSET_NAME_MAX} bytes`);
    }
}
function assertPrice(priceSats) {
    if (typeof priceSats !== 'bigint') {
        throw new Error('unitPriceSats must be a bigint');
    }
    if (priceSats <= 0n) {
        throw new Error('unitPriceSats must be > 0');
    }
    if (priceSats > 0x7fffffffffffffffn) {
        throw new Error('unitPriceSats exceeds int64 range');
    }
}
function assertSelector(selector) {
    if (!Number.isInteger(selector) || selector < 0 || selector > 0xff) {
        throw new Error('txHashSelector must be a single byte (0x00..0xff)');
    }
    if (selector === 0) {
        throw new Error('txHashSelector 0x00 is rejected by OP_TXHASH');
    }
}
/**
 * Build the scriptPubKey of a PQ Partial-Fill Sell Order covenant UTXO.
 */
function buildPartialFillScriptPQ(params) {
    const { paymentAddress, pubKeyCommitment, tokenId, unitPriceSats, txHashSelector = DEFAULT_PQ_TXHASH_SELECTOR } = params;
    assertCommitment(pubKeyCommitment);
    assertTokenId(tokenId);
    assertPrice(unitPriceSats);
    assertSelector(txHashSelector);
    const payment = encodeSellerScriptPubKey(paymentAddress);
    const tokenIdBytes = new TextEncoder().encode(tokenId);
    const b = new ScriptBuilder();
    // ───────── Cancel branch (PQ via OP_CHECKSIGFROMSTACK) ─────────
    // scriptSig expected: <sigPQ> <pubKeyPQ> OP_1
    // After OP_IF consumes the flag: [ sig, pubKey ]
    //
    // The selector MUST be pushed as a raw 1-byte element — consensus
    // (`interpreter.cpp` OP_TXHASH case) rejects any stack item of
    // size ≠ 1. Using `pushInt(selector)` would work for 1..127 but emit a
    // 2-byte CScriptNum for 0x80..0xff (the sign-disambiguation pad), which
    // makes OP_TXHASH fail with SCRIPT_ERR_TXHASH. See
    // `memory/project_covenant_v3_findings.md` bug B for details.
    b.op(OP_IF)
        .op(OP_DUP) // [ sig, pubKey, pubKey ]
        .op(OP_SHA256) // [ sig, pubKey, H(pubKey) ]
        .pushBytes(pubKeyCommitment) // [ sig, pubKey, H(pubKey), commitment ]
        .op(OP_EQUALVERIFY) // [ sig, pubKey ]
        .pushBytes(Uint8Array.of(txHashSelector)) // [ sig, pubKey, selector ] — always 1-byte stack item
        .op(OP_TXHASH) // [ sig, pubKey, txHash ]
        .op(OP_SWAP) // [ sig, txHash, pubKey ]
        .op(OP_CHECKSIGFROMSTACK) // [ 1 | 0 ]
        .op(OP_ELSE);
    // ───────── Partial-fill branch (identical layout to legacy) ─────────
    // scriptSig expected: <N> OP_0
    // Stack entering ELSE: [ N ]
    // 1. Payment value (output 0) >= N * unitPriceSats
    b.op(OP_DUP)
        .pushInt(unitPriceSats)
        .op(OP_MUL)
        .pushInt(0)
        .op(OP_OUTPUTVALUE)
        .op(OP_SWAP)
        .op(OP_GREATERTHANOREQUAL)
        .op(OP_VERIFY);
    // 2. Payment scriptPubKey (output 0) == payment.bytes
    b.pushInt(0)
        .op(OP_OUTPUTSCRIPT)
        .pushBytes(payment.bytes)
        .op(OP_EQUALVERIFY);
    // 3. Asset to buyer (output 1) amount == N
    b.op(OP_DUP)
        .pushInt(1)
        .pushInt(ASSETFIELD_AMOUNT)
        .op(OP_OUTPUTASSETFIELD)
        .op(OP_EQUALVERIFY);
    // 4. Asset to buyer (output 1) name == tokenId
    b.pushInt(1)
        .pushInt(ASSETFIELD_NAME)
        .op(OP_OUTPUTASSETFIELD)
        .pushBytes(tokenIdBytes)
        .op(OP_EQUALVERIFY);
    // 5. Remainder continuity (output 2) — same scriptPubKey as spent
    b.pushInt(2)
        .op(OP_OUTPUTSCRIPT)
        .pushInt(TXFIELD_SCRIPTPUBKEY)
        .op(OP_TXFIELD)
        .op(OP_EQUALVERIFY);
    // 6. Remainder tokenId
    b.pushInt(2)
        .pushInt(ASSETFIELD_NAME)
        .op(OP_OUTPUTASSETFIELD)
        .pushBytes(tokenIdBytes)
        .op(OP_EQUALVERIFY);
    // 7. Remainder amount == inputAssetAmount - N
    b.pushInt(2)
        .pushInt(ASSETFIELD_AMOUNT)
        .op(OP_OUTPUTASSETFIELD)
        .op(OP_OVER)
        .pushInt(0)
        .pushInt(ASSETFIELD_AMOUNT)
        .op(OP_INPUTASSETFIELD)
        .op(OP_SWAP)
        .op(OP_SUB)
        .op(OP_EQUALVERIFY);
    b.op(OP_DROP).pushInt(1);
    b.op(OP_ENDIF);
    return b.build();
}
function buildPartialFillScriptPQHex(params) {
    return bytesToHex(buildPartialFillScriptPQ(params));
}

/**
 * scriptSig builders for the Partial-Fill Sell Order covenant.
 *
 * These return the raw scriptSig bytes that unlock the covenant UTXO. The
 * surrounding transaction (inputs, outputs, fees, signatures on the buyer's
 * own inputs, etc.) is the caller's responsibility — stitch them together
 * with `@neuraiproject/neurai-create-transaction`.
 */
/**
 * Unlock the covenant via the public partial-fill branch.
 *
 * Layout on the stack before OP_IF executes (top → bottom):
 *   0   ← selects the OP_ELSE (fill) branch
 *   N   ← amount of asset the buyer is taking from this order
 *
 * so the scriptSig pushes `<N>` then `<0>`.
 *
 * @param amount  units of the asset the buyer is taking. Must be > 0 and
 *                strictly less than the amount locked in the order UTXO
 *                (equal would leave a zero-asset remainder, which isn't a
 *                valid Neurai transfer output).
 */
function buildFillScriptSig(amount) {
    if (typeof amount !== 'bigint') {
        throw new Error('amount must be a bigint');
    }
    if (amount <= 0n) {
        throw new Error('fill amount must be > 0');
    }
    return new ScriptBuilder()
        .pushInt(amount)
        .pushInt(0)
        .build();
}
function buildFillScriptSigHex(amount) {
    return bytesToHex(buildFillScriptSig(amount));
}
/**
 * Unlock the covenant via the seller's cancel branch.
 *
 * Stack before OP_IF (top → bottom):
 *   1       ← selects the OP_IF branch
 *   pubkey  ← consumed by OP_DUP OP_HASH160 … OP_EQUALVERIFY
 *   sig     ← consumed by OP_CHECKSIG
 *
 * so the scriptSig pushes `<sig> <pubkey> <1>`.
 *
 * The signature is on whatever sighash the caller picked; this builder does
 * not hash or sign, it only assembles the unlock script once a signature is
 * available.
 */
function buildCancelScriptSig(signatureDer, pubKey) {
    if (!(signatureDer instanceof Uint8Array) || signatureDer.length === 0) {
        throw new Error('signatureDer must be a non-empty Uint8Array');
    }
    if (!(pubKey instanceof Uint8Array) || (pubKey.length !== 33 && pubKey.length !== 65)) {
        throw new Error('pubKey must be a compressed (33B) or uncompressed (65B) secp256k1 key');
    }
    return new ScriptBuilder()
        .pushBytes(signatureDer)
        .pushBytes(pubKey)
        .pushInt(1)
        .build();
}
function buildCancelScriptSigHex(signatureDer, pubKey) {
    return bytesToHex(buildCancelScriptSig(signatureDer, pubKey));
}

/**
 * scriptSig builders for the PQ Partial-Fill Sell Order covenant.
 *
 * The fill branch is identical to the legacy variant (just pushes `<N> <0>`),
 * so callers reuse `buildFillScriptSig` from `./spend.ts`. Only the cancel
 * branch is different: it carries a full PQ pubkey (~1313 B) and signature
 * (~2421 B), which requires NIP-18's expanded element-size cap.
 */
/**
 * Build the scriptSig that unlocks the PQ cancel branch.
 *
 * Stack ordering pushed (bottom → top): `sig, pubkey, 1`.
 *
 * @param sigPQ   ML-DSA-44 signature over `SHA256(OP_TXHASH(selector))`,
 *                **with trailing sighash byte appended** (same convention as
 *                OP_CHECKSIG — CSFS strips it before verification). Expected
 *                length 2421 bytes for ML-DSA-44.
 * @param pubKey  Versioned PQ public key bytes, 1313 bytes (1-byte prefix
 *                + 1312-byte ML-DSA-44 key). Must hash (via SHA256) to the
 *                `pubKeyCommitment` embedded in the covenant scriptPubKey.
 */
function buildCancelScriptSigPQ(sigPQ, pubKey) {
    if (!(sigPQ instanceof Uint8Array) || sigPQ.length === 0) {
        throw new Error('sigPQ must be a non-empty Uint8Array');
    }
    if (sigPQ.length > 3072) {
        throw new Error(`sigPQ of ${sigPQ.length} bytes exceeds MAX_PQ_SCRIPT_ELEMENT_SIZE (3072)`);
    }
    if (!(pubKey instanceof Uint8Array) || pubKey.length === 0) {
        throw new Error('pubKey must be a non-empty Uint8Array');
    }
    if (pubKey.length > 3072) {
        throw new Error(`pubKey of ${pubKey.length} bytes exceeds MAX_PQ_SCRIPT_ELEMENT_SIZE (3072)`);
    }
    return new ScriptBuilder()
        .pushBytes(sigPQ)
        .pushBytes(pubKey)
        .pushInt(1)
        .build();
}
function buildCancelScriptSigPQHex(sigPQ, pubKey) {
    return bytesToHex(buildCancelScriptSigPQ(sigPQ, pubKey));
}

/**
 * Shared parsing primitives for strict covenant parsers. Each covenant
 * parser walks the exact byte layout emitted by its builder and fails on
 * any deviation; the primitives here centralize the cursor arithmetic,
 * pushdata decoding, and CScriptNum decoding so the legacy and PQ parsers
 * (and future covenant parsers) cannot drift in rigor.
 */
function makeCursor(bytes) {
    return { bytes, pos: 0 };
}
/** Consume one byte and verify it equals `expected`. */
function expectByte(c, expected, label) {
    if (c.pos >= c.bytes.length) {
        throw new Error(`parse: unexpected end of script while reading ${label}`);
    }
    const got = c.bytes[c.pos];
    if (got !== expected) {
        throw new Error(`parse: expected ${label} = 0x${expected.toString(16)} at offset ${c.pos}, got 0x${got.toString(16)}`);
    }
    c.pos += 1;
}
/** Fail if the cursor has not consumed every byte of the script. */
function assertTrailing(c) {
    if (c.pos !== c.bytes.length) {
        throw new Error(`parse: ${c.bytes.length - c.pos} trailing bytes after end of script`);
    }
}
/**
 * Read one pushdata element from the cursor. Supports direct pushes
 * (1..75 bytes), `OP_PUSHDATA1` and `OP_PUSHDATA2`. `OP_PUSHDATA4` is not
 * supported by any current covenant script and would overflow the
 * per-element cap anyway. Truncation is checked for all length fields
 * and payload ranges.
 */
function readPush(c, label) {
    if (c.pos >= c.bytes.length) {
        throw new Error(`parse: unexpected end of script while reading push for ${label}`);
    }
    const opcode = c.bytes[c.pos];
    c.pos += 1;
    // Short direct push: 1..75 bytes
    if (opcode >= 0x01 && opcode <= 0x4b) {
        const len = opcode;
        if (c.pos + len > c.bytes.length) {
            throw new Error(`parse: short push of ${len} bytes exceeds script length at ${label}`);
        }
        const data = c.bytes.slice(c.pos, c.pos + len);
        c.pos += len;
        return data;
    }
    // OP_PUSHDATA1
    if (opcode === 0x4c) {
        if (c.pos >= c.bytes.length) {
            throw new Error(`parse: truncated PUSHDATA1 length at ${label}`);
        }
        const len = c.bytes[c.pos];
        c.pos += 1;
        if (c.pos + len > c.bytes.length) {
            throw new Error(`parse: PUSHDATA1 of ${len} bytes exceeds script length at ${label}`);
        }
        const data = c.bytes.slice(c.pos, c.pos + len);
        c.pos += len;
        return data;
    }
    // OP_PUSHDATA2
    if (opcode === 0x4d) {
        if (c.pos + 2 > c.bytes.length) {
            throw new Error(`parse: truncated PUSHDATA2 length at ${label}`);
        }
        const len = c.bytes[c.pos] | (c.bytes[c.pos + 1] << 8);
        c.pos += 2;
        if (c.pos + len > c.bytes.length) {
            throw new Error(`parse: PUSHDATA2 of ${len} bytes exceeds script length at ${label}`);
        }
        const data = c.bytes.slice(c.pos, c.pos + len);
        c.pos += len;
        return data;
    }
    throw new Error(`parse: expected a pushdata opcode at ${label}, got 0x${opcode.toString(16)} at offset ${c.pos - 1}`);
}
/**
 * Decode a `CScriptNum` byte vector (little-endian sign-magnitude, up to
 * 8 bytes) into a BigInt. Empty vector encodes 0.
 */
function decodeScriptNum(data, label) {
    if (data.length === 0)
        return 0n;
    if (data.length > 8) {
        throw new Error(`parse: CScriptNum at ${label} exceeds 8 bytes`);
    }
    let n = 0n;
    for (let i = 0; i < data.length - 1; i += 1) {
        n |= BigInt(data[i]) << BigInt(8 * i);
    }
    const last = data[data.length - 1];
    n |= BigInt(last & 0x7f) << BigInt(8 * (data.length - 1));
    if (last & 0x80) {
        n = -n;
    }
    return n;
}
/**
 * Read a push as a non-negative CScriptNum. Recognises OP_1..OP_16
 * shorthand. `OP_0` is not accepted because the covenant callers use this
 * only for values that are strictly positive (prices, selectors, indices).
 */
function readPushPositiveInt(c, label) {
    if (c.pos >= c.bytes.length) {
        throw new Error(`parse: end of script at ${label}`);
    }
    const opcode = c.bytes[c.pos];
    if (opcode >= OP_1 && opcode <= 0x60) {
        c.pos += 1;
        return BigInt(opcode - OP_1 + 1);
    }
    const data = readPush(c, label);
    return decodeScriptNum(data, label);
}
/**
 * Read a 1-byte selector as an UNSIGNED 8-bit integer (0..255). Accepts
 * two on-wire encodings, because old vs new covenant builders differ:
 *   - `OP_1..OP_16` shorthand (single opcode) → values 1..16.
 *   - `0x01 <byte>` raw 1-byte push → any value 1..255.
 *
 * Values 0x80..0xff MUST use the raw-push form; the CScriptNum encoding
 * would need a 0x00 padding byte and become 2 bytes on-stack, which
 * consensus `OP_TXHASH` rejects. The builder in `script-pq.ts` emits the
 * raw-push form unconditionally; the parser stays lenient so covenants
 * built by older tools (using OP_N for small values) still round-trip.
 */
function readPushUint8(c, label) {
    if (c.pos >= c.bytes.length) {
        throw new Error(`parse: end of script at ${label}`);
    }
    const opcode = c.bytes[c.pos];
    if (opcode >= OP_1 && opcode <= 0x60) {
        c.pos += 1;
        return opcode - OP_1 + 1;
    }
    const data = readPush(c, label);
    if (data.length !== 1) {
        throw new Error(`parse: ${label} must be a single-byte push, got ${data.length} bytes`);
    }
    return data[0];
}

/**
 * Parser for the Partial-Fill Sell Order covenant.
 *
 * Extracts `(sellerPubKeyHash, unitPriceSats, tokenId)` from a scriptPubKey
 * that was produced by `buildPartialFillScript`. The parser walks the exact
 * byte layout emitted by the builder and fails on any deviation — this is
 * deliberate, so a downstream indexer can unambiguously classify a UTXO as
 * "partial-fill order" or "unknown script" with no false positives.
 */
/**
 * Parse a covenant scriptPubKey and extract its parameters. Throws with a
 * descriptive message if the bytes don't match the partial-fill template.
 */
function parsePartialFillScript(script, network = 'xna-test') {
    const bytes = typeof script === 'string' ? hexToBytes(script) : script;
    const c = makeCursor(bytes);
    // ───── Cancel branch prefix ─────
    expectByte(c, OP_IF, 'OP_IF');
    expectByte(c, OP_DUP, 'OP_DUP (cancel)');
    expectByte(c, OP_HASH160, 'OP_HASH160');
    const sellerPubKeyHash = readPush(c, 'sellerPubKeyHash');
    if (sellerPubKeyHash.length !== 20) {
        throw new Error(`parse: sellerPubKeyHash is ${sellerPubKeyHash.length} bytes, expected 20`);
    }
    expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (cancel)');
    expectByte(c, OP_CHECKSIG, 'OP_CHECKSIG (cancel)');
    expectByte(c, OP_ELSE, 'OP_ELSE');
    // ───── Payment value check ─────
    expectByte(c, OP_DUP, 'OP_DUP (price)');
    const unitPriceSats = readPushPositiveInt(c, 'unitPriceSats');
    expectByte(c, OP_MUL, 'OP_MUL');
    expectByte(c, OP_0, 'OP_0 (payment idx)');
    expectByte(c, OP_OUTPUTVALUE, 'OP_OUTPUTVALUE');
    expectByte(c, OP_SWAP, 'OP_SWAP');
    expectByte(c, OP_GREATERTHANOREQUAL, 'OP_GREATERTHANOREQUAL');
    expectByte(c, OP_VERIFY, 'OP_VERIFY (payment)');
    // ───── Payment scriptPubKey check ─────
    expectByte(c, OP_0, 'OP_0 (spk idx)');
    expectByte(c, OP_OUTPUTSCRIPT, 'OP_OUTPUTSCRIPT (payment)');
    const sellerSpk = readPush(c, 'sellerScriptPubKey');
    // Must be P2PKH with our PKH.
    const expectedSpk = new Uint8Array([
        OP_DUP, OP_HASH160, 0x14, ...sellerPubKeyHash, OP_EQUALVERIFY, OP_CHECKSIG
    ]);
    if (!bytesEqual(sellerSpk, expectedSpk)) {
        throw new Error('parse: embedded seller scriptPubKey does not match the cancel PKH');
    }
    expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (payment spk)');
    // ───── Buyer asset amount check (output 1) ─────
    expectByte(c, OP_DUP, 'OP_DUP (buyer amount)');
    expectByte(c, OP_1, 'OP_1 (buyer idx)');
    expectByte(c, OP_2, 'OP_2 (AMOUNT selector)');
    expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (buyer amount)');
    expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (buyer amount)');
    // ───── Buyer asset name check (output 1) ─────
    expectByte(c, OP_1, 'OP_1 (buyer idx)');
    expectByte(c, OP_1, 'OP_1 (NAME selector)');
    expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (buyer name)');
    const tokenIdBytes1 = readPush(c, 'tokenId #1');
    expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (buyer name)');
    // ───── Remainder continuity: same scriptPubKey ─────
    expectByte(c, OP_2, 'OP_2 (remainder idx)');
    expectByte(c, OP_OUTPUTSCRIPT, 'OP_OUTPUTSCRIPT (remainder)');
    expectByte(c, OP_3, 'OP_3 (TXFIELD selector)');
    expectByte(c, OP_TXFIELD, 'OP_TXFIELD');
    expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (remainder spk)');
    // ───── Remainder tokenId check ─────
    expectByte(c, OP_2, 'OP_2 (remainder idx)');
    expectByte(c, OP_1, 'OP_1 (NAME selector)');
    expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (remainder name)');
    const tokenIdBytes2 = readPush(c, 'tokenId #2');
    expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (remainder name)');
    // ───── Remainder amount == input amount - N ─────
    expectByte(c, OP_2, 'OP_2 (remainder idx)');
    expectByte(c, OP_2, 'OP_2 (AMOUNT selector)');
    expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (remainder amount)');
    expectByte(c, OP_OVER, 'OP_OVER');
    expectByte(c, OP_0, 'OP_0 (input idx)');
    expectByte(c, OP_2, 'OP_2 (AMOUNT selector)');
    expectByte(c, OP_INPUTASSETFIELD, 'OP_INPUTASSETFIELD');
    expectByte(c, OP_SWAP, 'OP_SWAP');
    expectByte(c, OP_SUB, 'OP_SUB');
    expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (remainder amount)');
    // ───── Tail ─────
    expectByte(c, OP_DROP, 'OP_DROP');
    expectByte(c, OP_1, 'OP_1 (true)');
    expectByte(c, OP_ENDIF, 'OP_ENDIF');
    assertTrailing(c);
    if (!bytesEqual(tokenIdBytes1, tokenIdBytes2)) {
        throw new Error('parse: tokenId bytes differ between buyer and remainder checks');
    }
    const tokenId = new TextDecoder('utf-8', { fatal: true }).decode(tokenIdBytes1);
    return {
        network,
        sellerPubKeyHash,
        unitPriceSats,
        tokenId,
        scriptHex: bytesToHex(bytes)
    };
}

/**
 * Parser for the PQ Partial-Fill Sell Order covenant. Returns the same
 * economic parameters as the legacy parser, plus the payment scriptPubKey
 * bytes (which may be P2PKH or AuthScript) and the configured TXHASH
 * selector.
 */
/** Quick discriminator without throwing — useful for indexers. */
function isPartialFillScriptPQ(script) {
    const bytes = typeof script === 'string' ? hexToBytes(script) : script;
    // PQ cancel starts with: OP_IF OP_DUP OP_SHA256
    return (bytes.length > 3 &&
        bytes[0] === OP_IF &&
        bytes[1] === OP_DUP &&
        bytes[2] === OP_SHA256);
}
/**
 * Parse a PQ partial-fill covenant. Throws if the bytes do not match the
 * exact layout produced by `buildPartialFillScriptPQ`.
 */
function parsePartialFillScriptPQ(script, network = 'xna-test') {
    const bytes = typeof script === 'string' ? hexToBytes(script) : script;
    const c = makeCursor(bytes);
    // ───── Cancel branch (PQ) ─────
    expectByte(c, OP_IF, 'OP_IF');
    expectByte(c, OP_DUP, 'OP_DUP (cancel)');
    expectByte(c, OP_SHA256, 'OP_SHA256');
    const pubKeyCommitment = readPush(c, 'pubKeyCommitment');
    if (pubKeyCommitment.length !== 32) {
        throw new Error(`parse-pq: pubKeyCommitment must be 32 bytes, got ${pubKeyCommitment.length}`);
    }
    expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (cancel)');
    // Selector is read as an unsigned byte — consensus OP_TXHASH treats the
    // on-stack element as uint8, and the builder emits a raw 1-byte push so
    // selectors 0x80..0xff round-trip correctly (plan v3 bug B).
    const txHashSelector = readPushUint8(c, 'txHashSelector');
    if (txHashSelector < 1) {
        throw new Error(`parse-pq: txHashSelector 0x00 is rejected by OP_TXHASH`);
    }
    expectByte(c, OP_TXHASH, 'OP_TXHASH');
    expectByte(c, OP_SWAP, 'OP_SWAP');
    expectByte(c, OP_CHECKSIGFROMSTACK, 'OP_CHECKSIGFROMSTACK');
    expectByte(c, OP_ELSE, 'OP_ELSE');
    // ───── Fill branch ─────
    expectByte(c, OP_DUP, 'OP_DUP (price)');
    const unitPriceSats = readPushPositiveInt(c, 'unitPriceSats');
    expectByte(c, OP_MUL, 'OP_MUL');
    expectByte(c, OP_0, 'OP_0 (payment idx)');
    expectByte(c, OP_OUTPUTVALUE, 'OP_OUTPUTVALUE');
    expectByte(c, OP_SWAP, 'OP_SWAP');
    expectByte(c, OP_GREATERTHANOREQUAL, 'OP_GE');
    expectByte(c, OP_VERIFY, 'OP_VERIFY');
    expectByte(c, OP_0, 'OP_0 (payment spk idx)');
    expectByte(c, OP_OUTPUTSCRIPT, 'OP_OUTPUTSCRIPT (payment)');
    const paymentScriptPubKey = readPush(c, 'paymentScriptPubKey');
    expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (payment)');
    expectByte(c, OP_DUP, 'OP_DUP (buyer amount)');
    expectByte(c, OP_1, 'OP_1 (buyer idx)');
    expectByte(c, OP_2, 'OP_2 (AMOUNT selector)');
    expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (buyer amount)');
    expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (buyer amount)');
    expectByte(c, OP_1, 'OP_1 (buyer idx)');
    expectByte(c, OP_1, 'OP_1 (NAME selector)');
    expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (buyer name)');
    const tokenIdBytes1 = readPush(c, 'tokenId #1');
    expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (buyer name)');
    expectByte(c, OP_2, 'OP_2 (remainder idx)');
    expectByte(c, OP_OUTPUTSCRIPT, 'OP_OUTPUTSCRIPT (remainder)');
    expectByte(c, OP_3, 'OP_3 (TXFIELD selector)');
    expectByte(c, OP_TXFIELD, 'OP_TXFIELD');
    expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (remainder spk)');
    expectByte(c, OP_2, 'OP_2 (remainder idx)');
    expectByte(c, OP_1, 'OP_1 (NAME selector)');
    expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (remainder name)');
    const tokenIdBytes2 = readPush(c, 'tokenId #2');
    expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (remainder name)');
    expectByte(c, OP_2, 'OP_2 (remainder idx)');
    expectByte(c, OP_2, 'OP_2 (AMOUNT selector)');
    expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (remainder amount)');
    expectByte(c, OP_OVER, 'OP_OVER');
    expectByte(c, OP_0, 'OP_0 (input idx)');
    expectByte(c, OP_2, 'OP_2 (AMOUNT selector)');
    expectByte(c, OP_INPUTASSETFIELD, 'OP_INPUTASSETFIELD');
    expectByte(c, OP_SWAP, 'OP_SWAP');
    expectByte(c, OP_SUB, 'OP_SUB');
    expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (remainder amount)');
    expectByte(c, OP_DROP, 'OP_DROP');
    expectByte(c, OP_1, 'OP_1 (true)');
    expectByte(c, OP_ENDIF, 'OP_ENDIF');
    assertTrailing(c);
    if (!bytesEqual(tokenIdBytes1, tokenIdBytes2)) {
        throw new Error('parse-pq: tokenId differs between buyer and remainder checks');
    }
    const tokenId = new TextDecoder('utf-8', { fatal: true }).decode(tokenIdBytes1);
    return {
        network,
        pubKeyCommitment,
        tokenId,
        unitPriceSats,
        txHashSelector,
        paymentScriptPubKey,
        scriptHex: bytesToHex(bytes)
    };
}

export { AUTHSCRIPT_LEGACY, AUTHSCRIPT_NOAUTH, AUTHSCRIPT_PQ, AUTHSCRIPT_REF, DEFAULT_PQ_TXHASH_SELECTOR, MULTISIG_MAX_PUBKEYS, NULLDATA_STANDARD_MAX_SIZE, ScriptBuilder, buildAuthScriptWitnessLegacy, buildAuthScriptWitnessNoAuth, buildAuthScriptWitnessPQ, buildAuthScriptWitnessRef, buildCancelScriptSig, buildCancelScriptSigHex, buildCancelScriptSigPQ, buildCancelScriptSigPQHex, buildFillScriptSig, buildFillScriptSigHex, buildPartialFillScript, buildPartialFillScriptHex, buildPartialFillScriptPQ, buildPartialFillScriptPQHex, bytesEqual, bytesToHex, concatBytes, encodeAuthScriptScriptPubKey, encodeMultisigRedeemScript, encodeMultisigRedeemScriptHex, encodeNullDataScript, encodeP2PKHScriptPubKey, encodeP2SHScriptPubKey, encodeP2WPKHScriptPubKey, encodeP2WSHScriptPubKey, encodeScriptNum, encodeSellerScriptPubKey, ensureHex, hexToBytes, isPartialFillScriptPQ, opcodes, parsePartialFillScript, parsePartialFillScriptPQ, pushBytes, pushHex, pushInt, splitAssetWrappedScriptPubKey };
//# sourceMappingURL=index.js.map
