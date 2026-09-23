/**
 * Neurai chain discriminator: `xna` = mainnet, `xna-test` = testnet/regtest.
 *
 * Only the chain matters here. In neurai-key 5 the label `xna` also names
 * the ECDSA witness v3 address type; parsed P2PKH hashes are formatted as
 * Legacy Base58 (neurai-key `xna-legacy` / `xna-legacy-test`) whatever this
 * label says.
 *
 * This type intentionally appears only on the **parse side** of the API —
 * as an optional argument to the parsers and as a field on the parsed
 * result types. It is **not** part of any builder's input.
 *
 * Rationale: the covenant scriptPubKey bytes do not encode network. A
 * legacy covenant is a fixed sequence of opcodes and a 20-byte PKH; a PQ
 * covenant is opcodes plus a 32-byte commitment and the raw bytes of the
 * payment scriptPubKey. None of those change between `xna` and
 * `xna-test`. What differs across networks is:
 *
 *   - The *address encoding* used by the caller (base58 prefix for
 *     P2PKH, bech32m HRP for AuthScript), validated by `decodeAddress`
 *     when the builder receives an address string.
 *   - The *consensus flags* gating the DePIN-Test opcodes; those live on
 *     the node, not in the script bytes.
 *
 * So builders take an address string (whose prefix already carries the
 * network) and parsers take an explicit `network` label (so the caller
 * can later format `sellerPubKeyHash` or interpret `paymentScriptPubKey`
 * in the correct context). Keep this split intact when adding new
 * covenants: do not reintroduce `network` into builder params.
 */
type Network = 'xna' | 'xna-test';
type PartialFillExpirationMode = 'height' | 'mtp';
interface PartialFillExpiration {
    /**
     * Chain context used to decide whether the sale is still active.
     *
     * - `height`: compare against the candidate block height.
     * - `mtp`: compare against the previous block's median time past.
     */
    mode: PartialFillExpirationMode;
    /**
     * Expiry boundary. Fills are valid only while `value > chainContext`.
     * At exactly this height / MTP, and after it, only the seller cancel branch
     * can spend the order.
     */
    value: bigint;
}
interface PartialFillOrderParams {
    /**
     * Seller destination. Must be a legacy P2PKH address (base58check,
     * "t..." on testnet, "N..." on mainnet). The legacy covenant uses
     * `OP_HASH160 + OP_CHECKSIG` in its cancel branch, so every bech32m
     * address (AuthScript v1 `nc1p…`, PQ v2 `pq1z…` and ECDSA v3 `nq1r…`,
     * whose program is a commitment, not a key hash) is rejected — use
     * `buildPartialFillScriptPQ` for those destinations. The decoded 20-byte
     * PKH is hardcoded into the covenant (cancel branch + payment scriptPubKey).
     */
    sellerAddress: string;
    /** Name of the asset being sold (e.g. "CAT"). */
    tokenId: string;
    /**
     * Price per single indivisible unit of the asset, expressed in satoshis of
     * XNA. The covenant multiplies this by the filled amount and enforces the
     * XNA output to Alice is `>=` that product.
     *
     * Example: selling at 1 XNA per whole token with `units = 0` (non-divisible)
     * means `unitPriceSats = 100_000_000n`.
     */
    unitPriceSats: bigint;
    /**
     * Optional sale expiry enforced with OP_CHAINCONTEXT. When set, both buyer
     * fill branches require `expiration.value > current height/MTP`. The seller
     * cancel branch remains available to recover the order.
     */
    expiration?: PartialFillExpiration;
}
interface ParsedPartialFillOrder {
    /** Network the parser was invoked with (used for downstream address formatting). */
    network: Network;
    /**
     * Seller's 20-byte pubkey hash, extracted from the covenant's cancel
     * branch. The caller can base58check-encode this with the network's
     * legacy prefix to recover the seller address when needed.
     */
    sellerPubKeyHash: Uint8Array;
    /** Asset name parsed from the covenant. */
    tokenId: string;
    /** Unit price parsed from the covenant, in XNA satoshis. */
    unitPriceSats: bigint;
    /** Optional sale expiry parsed from OP_CHAINCONTEXT gates. */
    expiration?: PartialFillExpiration;
    /** Script hex the parser was fed. */
    scriptHex: string;
}
interface OrderUtxo {
    txid: string;
    vout: number;
    /** scriptPubKey of the covenant UTXO (the output produced by the seller). */
    scriptPubKeyHex: string;
    /** Cantidad del asset dentro del UTXO covenant. */
    assetAmountRaw: bigint;
    /** Valor XNA del UTXO (normalmente el dust mínimo). */
    valueSats: bigint;
}
interface TxInputRef {
    txid: string;
    vout: number;
    sequence?: number;
    scriptSigHex?: string;
}
/**
 * Variant of the partial-fill order whose cancel branch validates a
 * post-quantum (ML-DSA-44) signature via `OP_CHECKSIGFROMSTACK`. Requires
 * both `SCRIPT_VERIFY_CHECKSIGFROMSTACK` and NIP-18's
 * `MAX_PQ_SCRIPT_ELEMENT_SIZE` to be active (testnet as of DePIN-Test with
 * NIP-18 deployed; mainnet after fork).
 */
interface PartialFillOrderPQParams {
    /**
     * Destination for the XNA payment to the seller: legacy P2PKH
     * (`N.../t...`), generic AuthScript v1 (`nc1p.../tnc1p...`), strict PQ v2
     * (`pq1z.../tpq1z...`) or strict ECDSA v3 (`nq1r.../tnq1r...`). The
     * covenant hardcodes the full scriptPubKey bytes (`OP_1`/`OP_2`/`OP_3`
     * prefix included) either way.
     */
    paymentAddress: string;
    /**
     * 32-byte commitment to the seller's PQ public key. The script checks
     * `SHA256(pubKey_on_stack) == pubKeyCommitment`. Caller must compute this
     * as SHA256 over the same pubKey bytes that will be pushed on spend
     * (typically 1313 bytes = 1-byte version prefix + 1312-byte ML-DSA-44 key).
     */
    pubKeyCommitment: Uint8Array;
    /** Asset name being sold. */
    tokenId: string;
    /** Price in XNA satoshis per indivisible unit of the asset. */
    unitPriceSats: bigint;
    /**
     * OP_TXHASH selector byte bound into the script. Default `0xff` (all
     * eight fields). The seller must sign `SHA256(OP_TXHASH(selector))` with
     * their PQ key at cancel time. See
     * `doc/new-opcodes-depin-branch.md` §2.1 for the bit → field mapping.
     */
    txHashSelector?: number;
    /**
     * Optional sale expiry enforced with OP_CHAINCONTEXT. When set, both buyer
     * fill branches require `expiration.value > current height/MTP`.
     */
    expiration?: PartialFillExpiration;
}
interface ParsedPartialFillOrderPQ extends Omit<PartialFillOrderPQParams, 'paymentAddress'> {
    /** Network the parser was invoked with (used for downstream address formatting). */
    network: Network;
    /** scriptPubKey bytes embedded in the covenant for the payment output. */
    paymentScriptPubKey: Uint8Array;
    scriptHex: string;
    /** Echoes the resolved selector so the caller can assert against a default. */
    txHashSelector: number;
}

/**
 * Minimal byte helpers. A subset of what `neurai-create-transaction` exposes,
 * duplicated here to keep this package free of runtime coupling beyond its
 * declared `dependencies` field. All sizes are little-endian, per Neurai.
 */
declare function ensureHex(hex: string, label?: string): string;
declare function hexToBytes(hex: string): Uint8Array;
declare function bytesToHex(bytes: Uint8Array): string;
declare function concatBytes(...parts: Uint8Array[]): Uint8Array;
declare function bytesEqual(a: Uint8Array, b: Uint8Array): boolean;

/**
 * Minimal CScriptNum encoding (Bitcoin consensus rules).
 *
 * - 0 → empty vector
 * - 1..16 → single opcode OP_1..OP_16 (handled in `pushInt`, not here)
 * - -1 → OP_1NEGATE (handled in `pushInt`)
 * - otherwise: sign-magnitude little-endian, with a sign bit on the last byte
 */
declare function encodeScriptNum(value: bigint | number): Uint8Array;
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
declare function pushBytes(data: Uint8Array): Uint8Array;
/**
 * Emit a minimally-encoded integer push. Uses OP_1NEGATE, OP_0 and OP_1..OP_16
 * when available to match how the node's own templates look on the wire.
 */
declare function pushInt(value: bigint | number): Uint8Array;
declare function pushHex(hex: string): Uint8Array;
/** Fluent assembler for readable script definitions. */
declare class ScriptBuilder {
    private readonly parts;
    op(...opcodes: number[]): this;
    pushInt(value: bigint | number): this;
    pushBytes(data: Uint8Array): this;
    pushHex(hex: string): this;
    raw(bytes: Uint8Array): this;
    build(): Uint8Array;
    buildHex(): string;
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
declare const OP_0 = 0;
declare const OP_FALSE = 0;
declare const OP_PUSHDATA1 = 76;
declare const OP_PUSHDATA2 = 77;
declare const OP_PUSHDATA4 = 78;
declare const OP_1NEGATE = 79;
declare const OP_RESERVED = 80;
declare const OP_1 = 81;
declare const OP_TRUE = 81;
declare const OP_2 = 82;
declare const OP_3 = 83;
declare const OP_4 = 84;
declare const OP_5 = 85;
declare const OP_6 = 86;
declare const OP_7 = 87;
declare const OP_8 = 88;
declare const OP_9 = 89;
declare const OP_10 = 90;
declare const OP_11 = 91;
declare const OP_12 = 92;
declare const OP_13 = 93;
declare const OP_14 = 94;
declare const OP_15 = 95;
declare const OP_16 = 96;
declare const OP_NOP = 97;
declare const OP_IF = 99;
declare const OP_NOTIF = 100;
declare const OP_ELSE = 103;
declare const OP_ENDIF = 104;
declare const OP_VERIFY = 105;
declare const OP_RETURN = 106;
declare const OP_TOALTSTACK = 107;
declare const OP_FROMALTSTACK = 108;
declare const OP_2DROP = 109;
declare const OP_2DUP = 110;
declare const OP_3DUP = 111;
declare const OP_2OVER = 112;
declare const OP_2ROT = 113;
declare const OP_2SWAP = 114;
declare const OP_IFDUP = 115;
declare const OP_DEPTH = 116;
declare const OP_DROP = 117;
declare const OP_DUP = 118;
declare const OP_NIP = 119;
declare const OP_OVER = 120;
declare const OP_PICK = 121;
declare const OP_ROLL = 122;
declare const OP_ROT = 123;
declare const OP_SWAP = 124;
declare const OP_TUCK = 125;
declare const OP_SIZE = 130;
declare const OP_EQUAL = 135;
declare const OP_EQUALVERIFY = 136;
declare const OP_1ADD = 139;
declare const OP_1SUB = 140;
declare const OP_NEGATE = 143;
declare const OP_ABS = 144;
declare const OP_NOT = 145;
declare const OP_0NOTEQUAL = 146;
declare const OP_ADD = 147;
declare const OP_SUB = 148;
declare const OP_MUL = 149;
declare const OP_DIV = 150;
declare const OP_MOD = 151;
declare const OP_BOOLAND = 154;
declare const OP_BOOLOR = 155;
declare const OP_NUMEQUAL = 156;
declare const OP_NUMEQUALVERIFY = 157;
declare const OP_NUMNOTEQUAL = 158;
declare const OP_LESSTHAN = 159;
declare const OP_GREATERTHAN = 160;
declare const OP_LESSTHANOREQUAL = 161;
declare const OP_GREATERTHANOREQUAL = 162;
declare const OP_MIN = 163;
declare const OP_MAX = 164;
declare const OP_WITHIN = 165;
declare const OP_RIPEMD160 = 166;
declare const OP_SHA1 = 167;
declare const OP_SHA256 = 168;
declare const OP_HASH160 = 169;
declare const OP_HASH256 = 170;
declare const OP_CODESEPARATOR = 171;
declare const OP_CHECKSIG = 172;
declare const OP_CHECKSIGVERIFY = 173;
declare const OP_CHECKMULTISIG = 174;
declare const OP_CHECKMULTISIGVERIFY = 175;
declare const OP_KECCAK256 = 186;
declare const OP_BLAKE2B = 187;
declare const OP_BLAKE3 = 200;
declare const OP_POSEIDON = 201;
declare const OP_SHA3_256 = 202;
declare const OP_SHA512 = 203;
declare const OP_CHECKSIG_ED25519 = 221;
declare const OP_CHECKSIGADD = 222;
declare const OP_NOP1 = 176;
declare const OP_NOP9 = 184;
declare const OP_NOP10 = 185;
declare const OP_CHECKLOCKTIMEVERIFY = 177;
declare const OP_CHECKSEQUENCEVERIFY = 178;
declare const OP_CHECKTEMPLATEVERIFY = 179;
declare const OP_CHECKSIGFROMSTACK = 180;
declare const OP_TXHASH = 181;
declare const OP_TXFIELD = 182;
declare const OP_TXLOCKTIME = 197;
declare const OP_OUTPUTVALUE = 204;
declare const OP_OUTPUTSCRIPT = 205;
declare const OP_INPUTCOUNT = 208;
declare const OP_OUTPUTCOUNT = 209;
declare const OP_OUTPUTASSETFIELD = 206;
declare const OP_INPUTASSETFIELD = 207;
declare const OP_XNA_ASSET = 192;
declare const OP_REFINPUTFIELD = 210;
declare const OP_REFINPUTASSETFIELD = 211;
declare const OP_REFINPUTCOUNT = 212;
declare const OP_OUTPUTAUTHCOMMITMENT = 213;
declare const OP_INPUTVALUE = 214;
declare const OP_CHAINCONTEXT = 215;
declare const CHAINCONTEXT_HEIGHT = 1;
declare const CHAINCONTEXT_MTP = 2;
declare const CHAINCONTEXT_CHAIN_ID = 3;
declare const OP_CHECKMERKLEINCLUSION = 193;
declare const OP_CAT = 126;
declare const OP_SPLIT = 183;
declare const OP_REVERSEBYTES = 188;
declare const TXFIELD_VALUE = 1;
declare const TXFIELD_AUTHSCRIPT_COMMITMENT = 2;
declare const TXFIELD_SCRIPTPUBKEY = 3;
declare const TXHASH_VERSION = 1;
declare const TXHASH_LOCKTIME = 2;
declare const TXHASH_INPUT_PREVOUTS = 4;
declare const TXHASH_INPUT_SEQUENCES = 8;
declare const TXHASH_OUTPUTS = 16;
declare const TXHASH_CURRENT_PREVOUT = 32;
declare const TXHASH_CURRENT_SEQUENCE = 64;
declare const TXHASH_CURRENT_INDEX = 128;
declare const TXHASH_ALL = 255;
declare const ASSETFIELD_NAME = 1;
declare const ASSETFIELD_AMOUNT = 2;
declare const ASSETFIELD_UNITS = 3;
declare const ASSETFIELD_REISSUABLE = 4;
declare const ASSETFIELD_HAS_IPFS = 5;
declare const ASSETFIELD_IPFS_HASH = 6;
declare const ASSETFIELD_TYPE = 7;

declare const opcodes_d_ASSETFIELD_AMOUNT: typeof ASSETFIELD_AMOUNT;
declare const opcodes_d_ASSETFIELD_HAS_IPFS: typeof ASSETFIELD_HAS_IPFS;
declare const opcodes_d_ASSETFIELD_IPFS_HASH: typeof ASSETFIELD_IPFS_HASH;
declare const opcodes_d_ASSETFIELD_NAME: typeof ASSETFIELD_NAME;
declare const opcodes_d_ASSETFIELD_REISSUABLE: typeof ASSETFIELD_REISSUABLE;
declare const opcodes_d_ASSETFIELD_TYPE: typeof ASSETFIELD_TYPE;
declare const opcodes_d_ASSETFIELD_UNITS: typeof ASSETFIELD_UNITS;
declare const opcodes_d_CHAINCONTEXT_CHAIN_ID: typeof CHAINCONTEXT_CHAIN_ID;
declare const opcodes_d_CHAINCONTEXT_HEIGHT: typeof CHAINCONTEXT_HEIGHT;
declare const opcodes_d_CHAINCONTEXT_MTP: typeof CHAINCONTEXT_MTP;
declare const opcodes_d_OP_0: typeof OP_0;
declare const opcodes_d_OP_0NOTEQUAL: typeof OP_0NOTEQUAL;
declare const opcodes_d_OP_1: typeof OP_1;
declare const opcodes_d_OP_10: typeof OP_10;
declare const opcodes_d_OP_11: typeof OP_11;
declare const opcodes_d_OP_12: typeof OP_12;
declare const opcodes_d_OP_13: typeof OP_13;
declare const opcodes_d_OP_14: typeof OP_14;
declare const opcodes_d_OP_15: typeof OP_15;
declare const opcodes_d_OP_16: typeof OP_16;
declare const opcodes_d_OP_1ADD: typeof OP_1ADD;
declare const opcodes_d_OP_1NEGATE: typeof OP_1NEGATE;
declare const opcodes_d_OP_1SUB: typeof OP_1SUB;
declare const opcodes_d_OP_2: typeof OP_2;
declare const opcodes_d_OP_2DROP: typeof OP_2DROP;
declare const opcodes_d_OP_2DUP: typeof OP_2DUP;
declare const opcodes_d_OP_2OVER: typeof OP_2OVER;
declare const opcodes_d_OP_2ROT: typeof OP_2ROT;
declare const opcodes_d_OP_2SWAP: typeof OP_2SWAP;
declare const opcodes_d_OP_3: typeof OP_3;
declare const opcodes_d_OP_3DUP: typeof OP_3DUP;
declare const opcodes_d_OP_4: typeof OP_4;
declare const opcodes_d_OP_5: typeof OP_5;
declare const opcodes_d_OP_6: typeof OP_6;
declare const opcodes_d_OP_7: typeof OP_7;
declare const opcodes_d_OP_8: typeof OP_8;
declare const opcodes_d_OP_9: typeof OP_9;
declare const opcodes_d_OP_ABS: typeof OP_ABS;
declare const opcodes_d_OP_ADD: typeof OP_ADD;
declare const opcodes_d_OP_BLAKE2B: typeof OP_BLAKE2B;
declare const opcodes_d_OP_BLAKE3: typeof OP_BLAKE3;
declare const opcodes_d_OP_BOOLAND: typeof OP_BOOLAND;
declare const opcodes_d_OP_BOOLOR: typeof OP_BOOLOR;
declare const opcodes_d_OP_CAT: typeof OP_CAT;
declare const opcodes_d_OP_CHAINCONTEXT: typeof OP_CHAINCONTEXT;
declare const opcodes_d_OP_CHECKLOCKTIMEVERIFY: typeof OP_CHECKLOCKTIMEVERIFY;
declare const opcodes_d_OP_CHECKMERKLEINCLUSION: typeof OP_CHECKMERKLEINCLUSION;
declare const opcodes_d_OP_CHECKMULTISIG: typeof OP_CHECKMULTISIG;
declare const opcodes_d_OP_CHECKMULTISIGVERIFY: typeof OP_CHECKMULTISIGVERIFY;
declare const opcodes_d_OP_CHECKSEQUENCEVERIFY: typeof OP_CHECKSEQUENCEVERIFY;
declare const opcodes_d_OP_CHECKSIG: typeof OP_CHECKSIG;
declare const opcodes_d_OP_CHECKSIGADD: typeof OP_CHECKSIGADD;
declare const opcodes_d_OP_CHECKSIGFROMSTACK: typeof OP_CHECKSIGFROMSTACK;
declare const opcodes_d_OP_CHECKSIGVERIFY: typeof OP_CHECKSIGVERIFY;
declare const opcodes_d_OP_CHECKSIG_ED25519: typeof OP_CHECKSIG_ED25519;
declare const opcodes_d_OP_CHECKTEMPLATEVERIFY: typeof OP_CHECKTEMPLATEVERIFY;
declare const opcodes_d_OP_CODESEPARATOR: typeof OP_CODESEPARATOR;
declare const opcodes_d_OP_DEPTH: typeof OP_DEPTH;
declare const opcodes_d_OP_DIV: typeof OP_DIV;
declare const opcodes_d_OP_DROP: typeof OP_DROP;
declare const opcodes_d_OP_DUP: typeof OP_DUP;
declare const opcodes_d_OP_ELSE: typeof OP_ELSE;
declare const opcodes_d_OP_ENDIF: typeof OP_ENDIF;
declare const opcodes_d_OP_EQUAL: typeof OP_EQUAL;
declare const opcodes_d_OP_EQUALVERIFY: typeof OP_EQUALVERIFY;
declare const opcodes_d_OP_FALSE: typeof OP_FALSE;
declare const opcodes_d_OP_FROMALTSTACK: typeof OP_FROMALTSTACK;
declare const opcodes_d_OP_GREATERTHAN: typeof OP_GREATERTHAN;
declare const opcodes_d_OP_GREATERTHANOREQUAL: typeof OP_GREATERTHANOREQUAL;
declare const opcodes_d_OP_HASH160: typeof OP_HASH160;
declare const opcodes_d_OP_HASH256: typeof OP_HASH256;
declare const opcodes_d_OP_IF: typeof OP_IF;
declare const opcodes_d_OP_IFDUP: typeof OP_IFDUP;
declare const opcodes_d_OP_INPUTASSETFIELD: typeof OP_INPUTASSETFIELD;
declare const opcodes_d_OP_INPUTCOUNT: typeof OP_INPUTCOUNT;
declare const opcodes_d_OP_INPUTVALUE: typeof OP_INPUTVALUE;
declare const opcodes_d_OP_KECCAK256: typeof OP_KECCAK256;
declare const opcodes_d_OP_LESSTHAN: typeof OP_LESSTHAN;
declare const opcodes_d_OP_LESSTHANOREQUAL: typeof OP_LESSTHANOREQUAL;
declare const opcodes_d_OP_MAX: typeof OP_MAX;
declare const opcodes_d_OP_MIN: typeof OP_MIN;
declare const opcodes_d_OP_MOD: typeof OP_MOD;
declare const opcodes_d_OP_MUL: typeof OP_MUL;
declare const opcodes_d_OP_NEGATE: typeof OP_NEGATE;
declare const opcodes_d_OP_NIP: typeof OP_NIP;
declare const opcodes_d_OP_NOP: typeof OP_NOP;
declare const opcodes_d_OP_NOP1: typeof OP_NOP1;
declare const opcodes_d_OP_NOP10: typeof OP_NOP10;
declare const opcodes_d_OP_NOP9: typeof OP_NOP9;
declare const opcodes_d_OP_NOT: typeof OP_NOT;
declare const opcodes_d_OP_NOTIF: typeof OP_NOTIF;
declare const opcodes_d_OP_NUMEQUAL: typeof OP_NUMEQUAL;
declare const opcodes_d_OP_NUMEQUALVERIFY: typeof OP_NUMEQUALVERIFY;
declare const opcodes_d_OP_NUMNOTEQUAL: typeof OP_NUMNOTEQUAL;
declare const opcodes_d_OP_OUTPUTASSETFIELD: typeof OP_OUTPUTASSETFIELD;
declare const opcodes_d_OP_OUTPUTAUTHCOMMITMENT: typeof OP_OUTPUTAUTHCOMMITMENT;
declare const opcodes_d_OP_OUTPUTCOUNT: typeof OP_OUTPUTCOUNT;
declare const opcodes_d_OP_OUTPUTSCRIPT: typeof OP_OUTPUTSCRIPT;
declare const opcodes_d_OP_OUTPUTVALUE: typeof OP_OUTPUTVALUE;
declare const opcodes_d_OP_OVER: typeof OP_OVER;
declare const opcodes_d_OP_PICK: typeof OP_PICK;
declare const opcodes_d_OP_POSEIDON: typeof OP_POSEIDON;
declare const opcodes_d_OP_PUSHDATA1: typeof OP_PUSHDATA1;
declare const opcodes_d_OP_PUSHDATA2: typeof OP_PUSHDATA2;
declare const opcodes_d_OP_PUSHDATA4: typeof OP_PUSHDATA4;
declare const opcodes_d_OP_REFINPUTASSETFIELD: typeof OP_REFINPUTASSETFIELD;
declare const opcodes_d_OP_REFINPUTCOUNT: typeof OP_REFINPUTCOUNT;
declare const opcodes_d_OP_REFINPUTFIELD: typeof OP_REFINPUTFIELD;
declare const opcodes_d_OP_RESERVED: typeof OP_RESERVED;
declare const opcodes_d_OP_RETURN: typeof OP_RETURN;
declare const opcodes_d_OP_REVERSEBYTES: typeof OP_REVERSEBYTES;
declare const opcodes_d_OP_RIPEMD160: typeof OP_RIPEMD160;
declare const opcodes_d_OP_ROLL: typeof OP_ROLL;
declare const opcodes_d_OP_ROT: typeof OP_ROT;
declare const opcodes_d_OP_SHA1: typeof OP_SHA1;
declare const opcodes_d_OP_SHA256: typeof OP_SHA256;
declare const opcodes_d_OP_SHA3_256: typeof OP_SHA3_256;
declare const opcodes_d_OP_SHA512: typeof OP_SHA512;
declare const opcodes_d_OP_SIZE: typeof OP_SIZE;
declare const opcodes_d_OP_SPLIT: typeof OP_SPLIT;
declare const opcodes_d_OP_SUB: typeof OP_SUB;
declare const opcodes_d_OP_SWAP: typeof OP_SWAP;
declare const opcodes_d_OP_TOALTSTACK: typeof OP_TOALTSTACK;
declare const opcodes_d_OP_TRUE: typeof OP_TRUE;
declare const opcodes_d_OP_TUCK: typeof OP_TUCK;
declare const opcodes_d_OP_TXFIELD: typeof OP_TXFIELD;
declare const opcodes_d_OP_TXHASH: typeof OP_TXHASH;
declare const opcodes_d_OP_TXLOCKTIME: typeof OP_TXLOCKTIME;
declare const opcodes_d_OP_VERIFY: typeof OP_VERIFY;
declare const opcodes_d_OP_WITHIN: typeof OP_WITHIN;
declare const opcodes_d_OP_XNA_ASSET: typeof OP_XNA_ASSET;
declare const opcodes_d_TXFIELD_AUTHSCRIPT_COMMITMENT: typeof TXFIELD_AUTHSCRIPT_COMMITMENT;
declare const opcodes_d_TXFIELD_SCRIPTPUBKEY: typeof TXFIELD_SCRIPTPUBKEY;
declare const opcodes_d_TXFIELD_VALUE: typeof TXFIELD_VALUE;
declare const opcodes_d_TXHASH_ALL: typeof TXHASH_ALL;
declare const opcodes_d_TXHASH_CURRENT_INDEX: typeof TXHASH_CURRENT_INDEX;
declare const opcodes_d_TXHASH_CURRENT_PREVOUT: typeof TXHASH_CURRENT_PREVOUT;
declare const opcodes_d_TXHASH_CURRENT_SEQUENCE: typeof TXHASH_CURRENT_SEQUENCE;
declare const opcodes_d_TXHASH_INPUT_PREVOUTS: typeof TXHASH_INPUT_PREVOUTS;
declare const opcodes_d_TXHASH_INPUT_SEQUENCES: typeof TXHASH_INPUT_SEQUENCES;
declare const opcodes_d_TXHASH_LOCKTIME: typeof TXHASH_LOCKTIME;
declare const opcodes_d_TXHASH_OUTPUTS: typeof TXHASH_OUTPUTS;
declare const opcodes_d_TXHASH_VERSION: typeof TXHASH_VERSION;
declare namespace opcodes_d {
  export {
    opcodes_d_ASSETFIELD_AMOUNT as ASSETFIELD_AMOUNT,
    opcodes_d_ASSETFIELD_HAS_IPFS as ASSETFIELD_HAS_IPFS,
    opcodes_d_ASSETFIELD_IPFS_HASH as ASSETFIELD_IPFS_HASH,
    opcodes_d_ASSETFIELD_NAME as ASSETFIELD_NAME,
    opcodes_d_ASSETFIELD_REISSUABLE as ASSETFIELD_REISSUABLE,
    opcodes_d_ASSETFIELD_TYPE as ASSETFIELD_TYPE,
    opcodes_d_ASSETFIELD_UNITS as ASSETFIELD_UNITS,
    opcodes_d_CHAINCONTEXT_CHAIN_ID as CHAINCONTEXT_CHAIN_ID,
    opcodes_d_CHAINCONTEXT_HEIGHT as CHAINCONTEXT_HEIGHT,
    opcodes_d_CHAINCONTEXT_MTP as CHAINCONTEXT_MTP,
    opcodes_d_OP_0 as OP_0,
    opcodes_d_OP_0NOTEQUAL as OP_0NOTEQUAL,
    opcodes_d_OP_1 as OP_1,
    opcodes_d_OP_10 as OP_10,
    opcodes_d_OP_11 as OP_11,
    opcodes_d_OP_12 as OP_12,
    opcodes_d_OP_13 as OP_13,
    opcodes_d_OP_14 as OP_14,
    opcodes_d_OP_15 as OP_15,
    opcodes_d_OP_16 as OP_16,
    opcodes_d_OP_1ADD as OP_1ADD,
    opcodes_d_OP_1NEGATE as OP_1NEGATE,
    opcodes_d_OP_1SUB as OP_1SUB,
    opcodes_d_OP_2 as OP_2,
    opcodes_d_OP_2DROP as OP_2DROP,
    opcodes_d_OP_2DUP as OP_2DUP,
    opcodes_d_OP_2OVER as OP_2OVER,
    opcodes_d_OP_2ROT as OP_2ROT,
    opcodes_d_OP_2SWAP as OP_2SWAP,
    opcodes_d_OP_3 as OP_3,
    opcodes_d_OP_3DUP as OP_3DUP,
    opcodes_d_OP_4 as OP_4,
    opcodes_d_OP_5 as OP_5,
    opcodes_d_OP_6 as OP_6,
    opcodes_d_OP_7 as OP_7,
    opcodes_d_OP_8 as OP_8,
    opcodes_d_OP_9 as OP_9,
    opcodes_d_OP_ABS as OP_ABS,
    opcodes_d_OP_ADD as OP_ADD,
    opcodes_d_OP_BLAKE2B as OP_BLAKE2B,
    opcodes_d_OP_BLAKE3 as OP_BLAKE3,
    opcodes_d_OP_BOOLAND as OP_BOOLAND,
    opcodes_d_OP_BOOLOR as OP_BOOLOR,
    opcodes_d_OP_CAT as OP_CAT,
    opcodes_d_OP_CHAINCONTEXT as OP_CHAINCONTEXT,
    opcodes_d_OP_CHECKLOCKTIMEVERIFY as OP_CHECKLOCKTIMEVERIFY,
    opcodes_d_OP_CHECKMERKLEINCLUSION as OP_CHECKMERKLEINCLUSION,
    opcodes_d_OP_CHECKMULTISIG as OP_CHECKMULTISIG,
    opcodes_d_OP_CHECKMULTISIGVERIFY as OP_CHECKMULTISIGVERIFY,
    opcodes_d_OP_CHECKSEQUENCEVERIFY as OP_CHECKSEQUENCEVERIFY,
    opcodes_d_OP_CHECKSIG as OP_CHECKSIG,
    opcodes_d_OP_CHECKSIGADD as OP_CHECKSIGADD,
    opcodes_d_OP_CHECKSIGFROMSTACK as OP_CHECKSIGFROMSTACK,
    opcodes_d_OP_CHECKSIGVERIFY as OP_CHECKSIGVERIFY,
    opcodes_d_OP_CHECKSIG_ED25519 as OP_CHECKSIG_ED25519,
    opcodes_d_OP_CHECKTEMPLATEVERIFY as OP_CHECKTEMPLATEVERIFY,
    opcodes_d_OP_CODESEPARATOR as OP_CODESEPARATOR,
    opcodes_d_OP_DEPTH as OP_DEPTH,
    opcodes_d_OP_DIV as OP_DIV,
    opcodes_d_OP_DROP as OP_DROP,
    opcodes_d_OP_DUP as OP_DUP,
    opcodes_d_OP_ELSE as OP_ELSE,
    opcodes_d_OP_ENDIF as OP_ENDIF,
    opcodes_d_OP_EQUAL as OP_EQUAL,
    opcodes_d_OP_EQUALVERIFY as OP_EQUALVERIFY,
    opcodes_d_OP_FALSE as OP_FALSE,
    opcodes_d_OP_FROMALTSTACK as OP_FROMALTSTACK,
    opcodes_d_OP_GREATERTHAN as OP_GREATERTHAN,
    opcodes_d_OP_GREATERTHANOREQUAL as OP_GREATERTHANOREQUAL,
    opcodes_d_OP_HASH160 as OP_HASH160,
    opcodes_d_OP_HASH256 as OP_HASH256,
    opcodes_d_OP_IF as OP_IF,
    opcodes_d_OP_IFDUP as OP_IFDUP,
    opcodes_d_OP_INPUTASSETFIELD as OP_INPUTASSETFIELD,
    opcodes_d_OP_INPUTCOUNT as OP_INPUTCOUNT,
    opcodes_d_OP_INPUTVALUE as OP_INPUTVALUE,
    opcodes_d_OP_KECCAK256 as OP_KECCAK256,
    opcodes_d_OP_LESSTHAN as OP_LESSTHAN,
    opcodes_d_OP_LESSTHANOREQUAL as OP_LESSTHANOREQUAL,
    opcodes_d_OP_MAX as OP_MAX,
    opcodes_d_OP_MIN as OP_MIN,
    opcodes_d_OP_MOD as OP_MOD,
    opcodes_d_OP_MUL as OP_MUL,
    opcodes_d_OP_NEGATE as OP_NEGATE,
    opcodes_d_OP_NIP as OP_NIP,
    opcodes_d_OP_NOP as OP_NOP,
    opcodes_d_OP_NOP1 as OP_NOP1,
    opcodes_d_OP_NOP10 as OP_NOP10,
    opcodes_d_OP_NOP9 as OP_NOP9,
    opcodes_d_OP_NOT as OP_NOT,
    opcodes_d_OP_NOTIF as OP_NOTIF,
    opcodes_d_OP_NUMEQUAL as OP_NUMEQUAL,
    opcodes_d_OP_NUMEQUALVERIFY as OP_NUMEQUALVERIFY,
    opcodes_d_OP_NUMNOTEQUAL as OP_NUMNOTEQUAL,
    opcodes_d_OP_OUTPUTASSETFIELD as OP_OUTPUTASSETFIELD,
    opcodes_d_OP_OUTPUTAUTHCOMMITMENT as OP_OUTPUTAUTHCOMMITMENT,
    opcodes_d_OP_OUTPUTCOUNT as OP_OUTPUTCOUNT,
    opcodes_d_OP_OUTPUTSCRIPT as OP_OUTPUTSCRIPT,
    opcodes_d_OP_OUTPUTVALUE as OP_OUTPUTVALUE,
    opcodes_d_OP_OVER as OP_OVER,
    opcodes_d_OP_PICK as OP_PICK,
    opcodes_d_OP_POSEIDON as OP_POSEIDON,
    opcodes_d_OP_PUSHDATA1 as OP_PUSHDATA1,
    opcodes_d_OP_PUSHDATA2 as OP_PUSHDATA2,
    opcodes_d_OP_PUSHDATA4 as OP_PUSHDATA4,
    opcodes_d_OP_REFINPUTASSETFIELD as OP_REFINPUTASSETFIELD,
    opcodes_d_OP_REFINPUTCOUNT as OP_REFINPUTCOUNT,
    opcodes_d_OP_REFINPUTFIELD as OP_REFINPUTFIELD,
    opcodes_d_OP_RESERVED as OP_RESERVED,
    opcodes_d_OP_RETURN as OP_RETURN,
    opcodes_d_OP_REVERSEBYTES as OP_REVERSEBYTES,
    opcodes_d_OP_RIPEMD160 as OP_RIPEMD160,
    opcodes_d_OP_ROLL as OP_ROLL,
    opcodes_d_OP_ROT as OP_ROT,
    opcodes_d_OP_SHA1 as OP_SHA1,
    opcodes_d_OP_SHA256 as OP_SHA256,
    opcodes_d_OP_SHA3_256 as OP_SHA3_256,
    opcodes_d_OP_SHA512 as OP_SHA512,
    opcodes_d_OP_SIZE as OP_SIZE,
    opcodes_d_OP_SPLIT as OP_SPLIT,
    opcodes_d_OP_SUB as OP_SUB,
    opcodes_d_OP_SWAP as OP_SWAP,
    opcodes_d_OP_TOALTSTACK as OP_TOALTSTACK,
    opcodes_d_OP_TRUE as OP_TRUE,
    opcodes_d_OP_TUCK as OP_TUCK,
    opcodes_d_OP_TXFIELD as OP_TXFIELD,
    opcodes_d_OP_TXHASH as OP_TXHASH,
    opcodes_d_OP_TXLOCKTIME as OP_TXLOCKTIME,
    opcodes_d_OP_VERIFY as OP_VERIFY,
    opcodes_d_OP_WITHIN as OP_WITHIN,
    opcodes_d_OP_XNA_ASSET as OP_XNA_ASSET,
    opcodes_d_TXFIELD_AUTHSCRIPT_COMMITMENT as TXFIELD_AUTHSCRIPT_COMMITMENT,
    opcodes_d_TXFIELD_SCRIPTPUBKEY as TXFIELD_SCRIPTPUBKEY,
    opcodes_d_TXFIELD_VALUE as TXFIELD_VALUE,
    opcodes_d_TXHASH_ALL as TXHASH_ALL,
    opcodes_d_TXHASH_CURRENT_INDEX as TXHASH_CURRENT_INDEX,
    opcodes_d_TXHASH_CURRENT_PREVOUT as TXHASH_CURRENT_PREVOUT,
    opcodes_d_TXHASH_CURRENT_SEQUENCE as TXHASH_CURRENT_SEQUENCE,
    opcodes_d_TXHASH_INPUT_PREVOUTS as TXHASH_INPUT_PREVOUTS,
    opcodes_d_TXHASH_INPUT_SEQUENCES as TXHASH_INPUT_SEQUENCES,
    opcodes_d_TXHASH_LOCKTIME as TXHASH_LOCKTIME,
    opcodes_d_TXHASH_OUTPUTS as TXHASH_OUTPUTS,
    opcodes_d_TXHASH_VERSION as TXHASH_VERSION,
  };
}

/**
 * Pay-to-Public-Key-Hash (P2PKH) scriptPubKey.
 * Layout: OP_DUP OP_HASH160 0x14 <20-byte PKH> OP_EQUALVERIFY OP_CHECKSIG
 */
declare function encodeP2PKHScriptPubKey(pubKeyHash: Uint8Array): Uint8Array;

/**
 * Native segwit v0 Pay-to-Witness-Public-Key-Hash (P2WPKH) scriptPubKey.
 * Layout: OP_0 0x14 <20-byte HASH160(pubKey)>
 *
 * Callers compute HASH160 externally (e.g. via neurai-key / their crypto
 * stack). This helper only encodes the scriptPubKey once the hash is known.
 */
declare function encodeP2WPKHScriptPubKey(pubKeyHash: Uint8Array): Uint8Array;

/**
 * Native segwit v0 Pay-to-Witness-Script-Hash (P2WSH) scriptPubKey.
 * Layout: OP_0 0x20 <32-byte SHA256(witnessScript)>
 *
 * This helper takes the SHA256 digest of the witness script directly. The
 * SHA256 is computed externally by the caller's crypto stack (kept out of
 * this library to avoid a hash dependency).
 */
declare function encodeP2WSHScriptPubKey(witnessScriptSha256: Uint8Array): Uint8Array;

/**
 * AuthScript scriptPubKey + witness-stack builders.
 *
 * AuthScript outputs encode a 32-byte commitment in a witness program:
 *   scriptPubKey = OP_n 0x20 <32-byte program>
 *
 *   OP_1  generic AuthScript v1 (nc1p… / tnc1p…): any auth type, any witnessScript
 *   OP_2  strict PQ v2 (pq1z… / tpq1z…): auth type 0x01, witnessScript OP_TRUE
 *   OP_3  strict ECDSA v3 (nq1r… / tnq1r…): auth type 0x02, witnessScript OP_TRUE
 *
 * The witness version is also the first byte of the commitment preimage:
 *   tagged_hash("NeuraiAuthScript", version || auth_descriptor || SHA256(witnessScript))
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
declare const AUTHSCRIPT_NOAUTH = 0;
declare const AUTHSCRIPT_PQ = 1;
declare const AUTHSCRIPT_LEGACY = 2;
/** NIP-015: reference-script spend mode. Not yet activated in consensus. */
declare const AUTHSCRIPT_REF = 3;
type AuthType = typeof AUTHSCRIPT_NOAUTH | typeof AUTHSCRIPT_PQ | typeof AUTHSCRIPT_LEGACY | typeof AUTHSCRIPT_REF;
/** AuthScript witness version: 1 generic, 2 strict PQ, 3 strict ECDSA. */
type AuthScriptWitnessVersion = 1 | 2 | 3;
/**
 * `OP_n 0x20 <program>` for witness version `n`. Defaults to the generic
 * AuthScript v1 (`OP_1`), which is what every covenant commits to.
 */
declare function encodeAuthScriptScriptPubKey(program: Uint8Array, witnessVersion?: AuthScriptWitnessVersion): Uint8Array;
interface AuthScriptWitnessLegacyInput {
    /** DER-encoded secp256k1 signature WITH trailing sighash byte. */
    signature: Uint8Array;
    /** Compressed (33B) or uncompressed (65B) secp256k1 public key. */
    pubKey: Uint8Array;
    /** Additional items consumed by the witnessScript, in bottom-to-top order. */
    args?: Uint8Array[];
    /** The full witnessScript whose hash equals the program of the output. */
    witnessScript: Uint8Array;
}
interface AuthScriptWitnessPQInput {
    /** ML-DSA-44 signature (~2421 B) WITH trailing sighash byte. */
    signature: Uint8Array;
    /** Versioned PQ pubkey (1-byte prefix + 1312-byte ML-DSA-44 key ≈ 1313 B). */
    pubKey: Uint8Array;
    args?: Uint8Array[];
    witnessScript: Uint8Array;
}
interface AuthScriptWitnessNoAuthInput {
    args?: Uint8Array[];
    witnessScript: Uint8Array;
}
interface AuthScriptWitnessRefInput {
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
declare function buildAuthScriptWitnessLegacy(input: AuthScriptWitnessLegacyInput): Uint8Array[];
/**
 * Build the witness stack for a PQ (ML-DSA-44) AuthScript spend.
 * NIP-018 must be active: both signature and pubKey are pushed as single
 * stack elements and may each be up to 3072 B.
 */
declare function buildAuthScriptWitnessPQ(input: AuthScriptWitnessPQInput): Uint8Array[];
/** Length of the versioned ML-DSA-44 pubkey the node expects (0x05 prefix + 1312 B). */
declare const STRICT_PQ_PUBKEY_LENGTH = 1313;
/** Version prefix of an ML-DSA-44 pubkey on the witness stack. */
declare const PQ_PUBKEY_PREFIX = 5;
interface StrictWitnessPQInput {
    /** ML-DSA-44 signature WITH trailing sighash byte. */
    signature: Uint8Array;
    /** Versioned PQ pubkey: 0x05 prefix + 1312-byte ML-DSA-44 key (1313 B). */
    pubKey: Uint8Array;
}
interface StrictWitnessECDSAInput {
    /** DER-encoded secp256k1 signature WITH trailing sighash byte. */
    signature: Uint8Array;
    /** Compressed secp256k1 public key (33 B). */
    pubKey: Uint8Array;
}
/**
 * Witness stack for spending a strict PQ witness v2 output (`pq1z…`):
 * exactly `[0x01, sig, pubKey, OP_TRUE]`. The node rejects any other
 * shape (extra arguments, another witnessScript) for the strict families.
 */
declare function buildStrictWitnessPQ(input: StrictWitnessPQInput): Uint8Array[];
/**
 * Witness stack for spending a strict ECDSA witness v3 output (`nq1r…`):
 * exactly `[0x02, sig, pubKey33, OP_TRUE]`. The node rejects uncompressed
 * keys for this family.
 */
declare function buildStrictWitnessECDSA(input: StrictWitnessECDSAInput): Uint8Array[];
/**
 * Build the witness stack for a NoAuth AuthScript spend. The spend is gated
 * by the witnessScript alone (covenants, hash-locks, time-locks, ...); no
 * signature or public key is carried.
 */
declare function buildAuthScriptWitnessNoAuth(input: AuthScriptWitnessNoAuthInput): Uint8Array[];
/**
 * Build the witness stack for a NIP-015 reference-script spend. The last
 * item is the 4-byte little-endian index into `tx.vrefin` that locates the
 * reference-script carrier output; the interpreter resolves the `refScript`
 * from that carrier at validation time.
 *
 * NOTE: NIP-015 is not yet activated in consensus. This builder emits the
 * spec-conformant witness for forward compatibility and testnet experiments.
 */
declare function buildAuthScriptWitnessRef(input: AuthScriptWitnessRefInput): Uint8Array[];

/**
 * Provably-unspendable OP_RETURN (null-data) output scripts.
 * Layout: OP_RETURN <push> [<push> ...]
 *
 * Neurai inherits the Bitcoin Core standard policy cap of 80 bytes of
 * payload for a relayed null-data output. Outputs over that cap are still
 * consensus-valid but will not be relayed by default mempool policy; use
 * the `allowNonStandard` option to opt in explicitly.
 */
declare const NULLDATA_STANDARD_MAX_SIZE = 80;
interface EncodeNullDataOptions {
    /** Bypass the 80-byte standard-policy cap. Default: false. */
    allowNonStandard?: boolean;
}
declare function encodeNullDataScript(payload: Uint8Array | Uint8Array[], options?: EncodeNullDataOptions): Uint8Array;

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
declare const MULTISIG_MAX_PUBKEYS = 20;
interface MultisigParams {
    /** Number of required signatures (1..n). */
    m: number;
    /** Compressed (33B) or uncompressed (65B) secp256k1 pubkeys, ordered. */
    pubKeys: Uint8Array[];
}
declare function encodeMultisigRedeemScript({ m, pubKeys }: MultisigParams): Uint8Array;
declare function encodeMultisigRedeemScriptHex(params: MultisigParams): string;
/**
 * P2SH scriptPubKey wrapping any redeem script. Pass the 20-byte HASH160 of
 * the redeem script (RIPEMD160(SHA256(redeemScript))) — compute it
 * externally via the caller's crypto stack.
 */
declare function encodeP2SHScriptPubKey(redeemScriptHash160: Uint8Array): Uint8Array;

/**
 * Address helpers. Wraps `decodeAddress` from
 * `@neuraiproject/neurai-create-transaction` to produce the exact
 * scriptPubKey bytes a covenant needs to hardcode. The actual
 * scriptPubKey encoders live in `./standard/*`; this module delegates.
 *
 * Every Neurai destination type is supported for the payment output
 * (output[0]):
 *   - Legacy P2PKH (base58check)                     → `76a914<20>88ac`
 *   - Generic AuthScript witness v1 (nc1p… / tnc1p…) → `5120<32>`
 *   - Strict PQ witness v2 (pq1z… / tpq1z…)          → `5220<32>`
 *   - Strict ECDSA witness v3 (nq1r… / tnq1r…)       → `5320<32>`
 */

/**
 * `authscript` is the generic witness v1; `pq` and `ecdsa` are the strict
 * witness v2 and v3 families.
 */
type SellerAddressKind = 'p2pkh' | 'authscript' | 'pq' | 'ecdsa';
interface SellerScriptPubKey {
    kind: SellerAddressKind;
    /** Witness version of an AuthScript destination (1, 2 or 3). */
    witnessVersion?: AuthScriptWitnessVersion;
    /** Raw scriptPubKey bytes that output[0] of a fill tx must equal. */
    bytes: Uint8Array;
    /**
     * Address-specific hash: 20-byte PKH for P2PKH, 32-byte program for
     * AuthScript. Used by the cancel branch (either as the HASH160 target or
     * as the SHA256(pubKey) commitment).
     */
    hash: Uint8Array;
}

/**
 * Resolve any accepted seller address string into its scriptPubKey.
 * The returned bytes are what the covenant will hardcode and later verify
 * via `OP_OUTPUTSCRIPT == <bytes>`.
 */
declare function encodeSellerScriptPubKey(address: string): SellerScriptPubKey;

/**
 * Asset-transfer wrapper split helper.
 *
 * Neurai asset UTXOs have a scriptPubKey of the form
 *
 *     <prefix scriptPubKey bytes> OP_XNA_ASSET <pushdata(payload)> OP_DROP
 *
 * where `prefix` is the recipient's standard script (typically a P2PKH, an
 * AuthScript `OP_1`/`OP_2`/`OP_3` witness program, or a bare covenant such
 * as the partial-fill sell order), and `payload` serializes a `CAssetTransfer`:
 *
 *     payload = marker ("rvn" 0x72 0x76 0x6e | "xna" 0x78 0x6e 0x61)
 *             || type_marker (0x74 transfer)
 *             || VarStr(assetName)
 *             || int64LE(amountRaw)
 *             [ || messageRef (optional) || int64LE(expireTime) (optional) ]
 *
 * NIP-040: mainnet still emits the Ravencoin-inherited "rvn" marker;
 * testnet/regtest emit "xna" after activation. Both are accepted when
 * reading — the detected marker is surfaced on the parsed payload.
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
/** NIP-040 asset payload marker: legacy `rvn` or post-activation `xna`. */
type AssetMarker = 'rvn' | 'xna';
interface AssetTransferPayload {
    /** ASCII asset name as declared in the VarStr field. */
    assetName: string;
    /** Raw satoshi-scaled amount from the int64LE field. Display units = raw / 1e8. */
    amountRaw: bigint;
    /** Marker detected at the start of the payload (`rvn` | `xna`). */
    marker: AssetMarker;
    /** Hex of the full payload bytes (starting at the marker magic, ending at
     *  the last byte before OP_DROP). Includes optional tail when present. */
    payloadHex: string;
}
interface SplitAssetWrappedResult {
    /** Bytes of the scriptPubKey BEFORE the OP_XNA_ASSET wrapper, hex. Equal
     *  to the input when the script carries no asset wrapper. */
    prefixHex: string;
    /** Parsed asset-transfer data, or null if the input has no asset wrapper. */
    assetTransfer: AssetTransferPayload | null;
}
/**
 * Parse an asset-transfer-wrapped scriptPubKey. Accepts both wrapped and
 * bare forms. Throws on structural malformation (truncated pushdata,
 * missing OP_DROP after payload, bad magic, unsupported pushdata width).
 */
declare function splitAssetWrappedScriptPubKey(spkHex: string): SplitAssetWrappedResult;

/**
 * Partial-Fill Sell Order covenant script (three-branch).
 *
 * The covenant has three branches selected by the top of the unlock stack:
 *
 *   OP_IF                  ← Cancel: seller signs, recovers remainder.
 *   OP_ELSE OP_IF          ← Full fill: buyer drains the covenant entirely.
 *                            No continuation output is required.
 *   OP_ELSE OP_ELSE        ← Partial fill: buyer takes N < total. A
 *                            continuation UTXO at vout[2] preserves the
 *                            covenant with amount = total - N.
 *
 * Output layout:
 *
 *   output[0] = XNA payment to seller   (value >= N * unitPriceSats)
 *   output[1] = asset to buyer          (tokenId, amount == N)
 *   output[2] = covenant continuation   (only for partial fill;
 *                                        same AuthScript commitment,
 *                                        amount == inputAmount - N)
 *   output[3+] = optional buyer change  (not constrained by the covenant)
 *
 * Continuity — the remainder UTXO reuses the spent covenant's AuthScript v1
 * commitment via `OP_OUTPUTAUTHCOMMITMENT(2) == OP_TXFIELD(0x02)` (NIP-023).
 * Comparing commitments rather than full scriptPubKeys is mandatory because
 * the remainder's asset wrapper carries a different `amountRaw` than the
 * spent UTXO's wrapper.
 *
 * Unlock stack shapes (scriptSig pushes, top → bottom):
 *
 *   Cancel:        <sig> <pubkey> <1>
 *   Full fill:            <1>       <0>       (full-flag=1, cancel-flag=0)
 *   Partial fill:  <N>    <0>       <0>       (N, full-flag=0, cancel-flag=0)
 *
 * The cancel branch uses classical ECDSA (`OP_HASH160 + OP_CHECKSIG`) and
 * commits to a 20-byte PKH — this variant only accepts legacy P2PKH
 * addresses as the seller destination. For AuthScript bech32m destinations
 * and post-quantum signing, use `buildPartialFillScriptPQ`.
 */

/**
 * Build the `scriptPubKey` of a Partial-Fill Sell Order covenant UTXO.
 * Returns raw bytes; wrap with `bytesToHex` for wire format.
 */
declare function buildPartialFillScript(params: PartialFillOrderParams): Uint8Array;
/** Hex convenience wrapper for `buildPartialFillScript`. */
declare function buildPartialFillScriptHex(params: PartialFillOrderParams): string;

/**
 * PQ (post-quantum) variant of the Partial-Fill Sell Order covenant.
 *
 * Identical fill branches (full + partial) to the legacy covenant, but the
 * **cancel** branch accepts an ML-DSA-44 signature instead of an ECDSA one.
 * This requires:
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
 *
 * Fill branches are identical in structure to the legacy variant — see
 * `./script.ts` for the three-branch layout description.
 */

declare const DEFAULT_PQ_TXHASH_SELECTOR = 255;
/**
 * Build the scriptPubKey of a PQ Partial-Fill Sell Order covenant UTXO.
 */
declare function buildPartialFillScriptPQ(params: PartialFillOrderPQParams): Uint8Array;
declare function buildPartialFillScriptPQHex(params: PartialFillOrderPQParams): string;

/**
 * scriptSig builders for the Partial-Fill Sell Order covenant.
 *
 * These return the raw scriptSig bytes that unlock the covenant UTXO. The
 * surrounding transaction (inputs, outputs, fees, signatures on the buyer's
 * own inputs, etc.) is the caller's responsibility — stitch them together
 * with `@neuraiproject/neurai-create-transaction`.
 */
/**
 * Unlock the covenant via the public fill branches.
 *
 *   amount === total  →  full-fill branch. The entire covenant drains to
 *                        vout[1]; no vout[2] continuation is emitted.
 *   amount <  total   →  partial-fill branch. vout[2] re-locks the
 *                        continuation (`total - amount` units).
 *
 * Unlock stack shapes (pushed bottom → top):
 *
 *   Full fill:     <1> <0>         ( full-flag=1, cancel-flag=0 )
 *   Partial fill:  <N> <0> <0>     ( N, full-flag=0, cancel-flag=0 )
 *
 * @param amount  units the buyer is taking. Must be > 0 and ≤ total.
 * @param total   current asset amount locked in the covenant UTXO. The
 *                builder reads this to decide whether to emit the full-fill
 *                or partial-fill witness — consensus uses `OP_INPUTASSETFIELD`
 *                inside the covenant to check it independently, so the value
 *                passed here must match on-chain reality or the script fails.
 */
declare function buildFillScriptSig(amount: bigint, total: bigint): Uint8Array;
declare function buildFillScriptSigHex(amount: bigint, total: bigint): string;
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
declare function buildCancelScriptSig(signatureDer: Uint8Array, pubKey: Uint8Array): Uint8Array;
declare function buildCancelScriptSigHex(signatureDer: Uint8Array, pubKey: Uint8Array): string;

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
declare function buildCancelScriptSigPQ(sigPQ: Uint8Array, pubKey: Uint8Array): Uint8Array;
declare function buildCancelScriptSigPQHex(sigPQ: Uint8Array, pubKey: Uint8Array): string;

/**
 * Witness-stack builders for the Partial-Fill Sell Order covenant.
 *
 * When the covenant lives behind an AuthScript commitment (the only
 * asset-compatible deployment since the node's OP_XNA_ASSET placement rules
 * — bare covenant outputs can no longer carry assets), the unlock data goes
 * in the witness, not the scriptSig. The scriptSig builders in `spend.ts`
 * return a serialized script that PUSHES the elements; a witness needs the
 * elements THEMSELVES, one per stack slot, so those blobs cannot be reused
 * as a single `args` entry.
 *
 * These builders return the raw `args` stack (bottom → top), mirroring the
 * shapes documented in `spend.ts`:
 *
 *   Full fill:     [ <1>, <0> ]
 *   Partial fill:  [ <N>, <0>, <0> ]
 *   Cancel:        [ <sig>, <pubkey>, <1> ]
 *
 * Numbers are minimal CScriptNum stack values (0 = empty element). Wrap the
 * result with `buildAuthScriptWitnessNoAuth({ args, witnessScript: covenant })`
 * (from `standard/authscript.ts`) to get the final `[0x00, ...args, covenant]`
 * witness, and serialize the spending transaction with
 * `serializeTransaction` from `@neuraiproject/neurai-create-transaction`
 * (0.5.1+, witness elements as hex strings: `witness.map(bytesToHex)`).
 */
/**
 * Witness `args` for the public fill branches. Same semantics and
 * validations as `buildFillScriptSig`.
 */
declare function buildFillWitnessStack(amount: bigint, total: bigint): Uint8Array[];
/**
 * Witness `args` for the seller's ECDSA cancel branch. Same semantics and
 * validations as `buildCancelScriptSig`.
 */
declare function buildCancelWitnessStack(signatureDer: Uint8Array, pubKey: Uint8Array): Uint8Array[];
/**
 * Witness `args` for the seller's PQ (ML-DSA-44) cancel branch. Same
 * semantics and validations as `buildCancelScriptSigPQ`.
 */
declare function buildCancelWitnessStackPQ(sigPQ: Uint8Array, pubKey: Uint8Array): Uint8Array[];

/**
 * Parser for the Partial-Fill Sell Order covenant (three-branch).
 *
 * Extracts `(sellerPubKeyHash, unitPriceSats, tokenId)` from a scriptPubKey
 * that was produced by `buildPartialFillScript`. Walks the exact byte
 * layout emitted by the builder and fails on any deviation — this is
 * deliberate, so a downstream indexer can unambiguously classify a UTXO as
 * "partial-fill order" or "unknown script" with no false positives.
 *
 * The full-fill and partial-fill branches share `(sellerScriptPubKey,
 * unitPriceSats, tokenId)`. The parser reads both branches and verifies
 * consistency; inconsistency throws.
 */

/**
 * Parse a covenant scriptPubKey and extract its parameters. Throws with a
 * descriptive message if the bytes don't match the partial-fill template.
 */
declare function parsePartialFillScript(script: Uint8Array | string, network?: Network): ParsedPartialFillOrder;

/**
 * Parser for the PQ Partial-Fill Sell Order covenant (three-branch).
 * Returns the same economic parameters as the legacy parser, plus the
 * payment scriptPubKey bytes (which may be P2PKH or AuthScript) and the
 * configured TXHASH selector.
 *
 * The full-fill and partial-fill branches share `(paymentScriptPubKey,
 * unitPriceSats, tokenId)`. The parser reads both branches and verifies
 * consistency; inconsistency throws.
 */

/** Quick discriminator without throwing — useful for indexers. */
declare function isPartialFillScriptPQ(script: Uint8Array | string): boolean;
/**
 * Parse a PQ partial-fill covenant. Throws if the bytes do not match the
 * exact layout produced by `buildPartialFillScriptPQ`.
 */
declare function parsePartialFillScriptPQ(script: Uint8Array | string, network?: Network): ParsedPartialFillOrderPQ;

export { AUTHSCRIPT_LEGACY, AUTHSCRIPT_NOAUTH, AUTHSCRIPT_PQ, AUTHSCRIPT_REF, DEFAULT_PQ_TXHASH_SELECTOR, MULTISIG_MAX_PUBKEYS, NULLDATA_STANDARD_MAX_SIZE, PQ_PUBKEY_PREFIX, STRICT_PQ_PUBKEY_LENGTH, ScriptBuilder, buildAuthScriptWitnessLegacy, buildAuthScriptWitnessNoAuth, buildAuthScriptWitnessPQ, buildAuthScriptWitnessRef, buildCancelScriptSig, buildCancelScriptSigHex, buildCancelScriptSigPQ, buildCancelScriptSigPQHex, buildCancelWitnessStack, buildCancelWitnessStackPQ, buildFillScriptSig, buildFillScriptSigHex, buildFillWitnessStack, buildPartialFillScript, buildPartialFillScriptHex, buildPartialFillScriptPQ, buildPartialFillScriptPQHex, buildStrictWitnessECDSA, buildStrictWitnessPQ, bytesEqual, bytesToHex, concatBytes, encodeAuthScriptScriptPubKey, encodeMultisigRedeemScript, encodeMultisigRedeemScriptHex, encodeNullDataScript, encodeP2PKHScriptPubKey, encodeP2SHScriptPubKey, encodeP2WPKHScriptPubKey, encodeP2WSHScriptPubKey, encodeScriptNum, encodeSellerScriptPubKey, ensureHex, hexToBytes, isPartialFillScriptPQ, opcodes_d as opcodes, parsePartialFillScript, parsePartialFillScriptPQ, pushBytes, pushHex, pushInt, splitAssetWrappedScriptPubKey };
export type { AssetMarker, AssetTransferPayload, AuthScriptWitnessLegacyInput, AuthScriptWitnessNoAuthInput, AuthScriptWitnessPQInput, AuthScriptWitnessRefInput, AuthScriptWitnessVersion, AuthType, EncodeNullDataOptions, MultisigParams, Network, OrderUtxo, ParsedPartialFillOrder, ParsedPartialFillOrderPQ, PartialFillExpiration, PartialFillExpirationMode, PartialFillOrderPQParams, PartialFillOrderParams, SellerAddressKind, SellerScriptPubKey, SplitAssetWrappedResult, StrictWitnessECDSAInput, StrictWitnessPQInput, TxInputRef };
