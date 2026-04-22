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
export const OP_0 = 0x00;
export const OP_FALSE = OP_0;
export const OP_PUSHDATA1 = 0x4c;
export const OP_PUSHDATA2 = 0x4d;
export const OP_PUSHDATA4 = 0x4e;
export const OP_1NEGATE = 0x4f;
export const OP_RESERVED = 0x50;
export const OP_1 = 0x51;
export const OP_TRUE = OP_1;
export const OP_2 = 0x52;
export const OP_3 = 0x53;
export const OP_4 = 0x54;
export const OP_5 = 0x55;
export const OP_6 = 0x56;
export const OP_7 = 0x57;
export const OP_8 = 0x58;
export const OP_9 = 0x59;
export const OP_10 = 0x5a;
export const OP_11 = 0x5b;
export const OP_12 = 0x5c;
export const OP_13 = 0x5d;
export const OP_14 = 0x5e;
export const OP_15 = 0x5f;
export const OP_16 = 0x60;

// ---------- Control flow ----------
export const OP_NOP = 0x61;
export const OP_IF = 0x63;
export const OP_NOTIF = 0x64;
export const OP_ELSE = 0x67;
export const OP_ENDIF = 0x68;
export const OP_VERIFY = 0x69;
export const OP_RETURN = 0x6a;

// ---------- Stack ----------
export const OP_TOALTSTACK = 0x6b;
export const OP_FROMALTSTACK = 0x6c;
export const OP_2DROP = 0x6d;
export const OP_2DUP = 0x6e;
export const OP_3DUP = 0x6f;
export const OP_2OVER = 0x70;
export const OP_2ROT = 0x71;
export const OP_2SWAP = 0x72;
export const OP_IFDUP = 0x73;
export const OP_DEPTH = 0x74;
export const OP_DROP = 0x75;
export const OP_DUP = 0x76;
export const OP_NIP = 0x77;
export const OP_OVER = 0x78;
export const OP_PICK = 0x79;
export const OP_ROLL = 0x7a;
export const OP_ROT = 0x7b;
export const OP_SWAP = 0x7c;
export const OP_TUCK = 0x7d;

// ---------- Splice ----------
export const OP_SIZE = 0x82;

// ---------- Bitwise / comparison ----------
export const OP_EQUAL = 0x87;
export const OP_EQUALVERIFY = 0x88;

// ---------- Unary numeric ----------
export const OP_1ADD = 0x8b;
export const OP_1SUB = 0x8c;
export const OP_NEGATE = 0x8f;
export const OP_ABS = 0x90;
export const OP_NOT = 0x91;
export const OP_0NOTEQUAL = 0x92;

// ---------- Arithmetic (64-bit after SCRIPT_VERIFY_64BIT_INTEGERS) ----------
export const OP_ADD = 0x93;
export const OP_SUB = 0x94;
export const OP_MUL = 0x95;
export const OP_DIV = 0x96;
export const OP_MOD = 0x97;

// ---------- Boolean / numeric comparison ----------
export const OP_BOOLAND = 0x9a;
export const OP_BOOLOR = 0x9b;
export const OP_NUMEQUAL = 0x9c;
export const OP_NUMEQUALVERIFY = 0x9d;
export const OP_NUMNOTEQUAL = 0x9e;
export const OP_LESSTHAN = 0x9f;
export const OP_GREATERTHAN = 0xa0;
export const OP_LESSTHANOREQUAL = 0xa1;
export const OP_GREATERTHANOREQUAL = 0xa2;
export const OP_MIN = 0xa3;
export const OP_MAX = 0xa4;
export const OP_WITHIN = 0xa5;

// ---------- Crypto ----------
export const OP_RIPEMD160 = 0xa6;
export const OP_SHA1 = 0xa7;
export const OP_SHA256 = 0xa8;
export const OP_HASH160 = 0xa9;
export const OP_HASH256 = 0xaa;
export const OP_CODESEPARATOR = 0xab;
export const OP_CHECKSIG = 0xac;
export const OP_CHECKSIGVERIFY = 0xad;
export const OP_CHECKMULTISIG = 0xae;
export const OP_CHECKMULTISIGVERIFY = 0xaf;

// ---------- Expansion / NOPs ----------
// Only the NOPs not aliased by DePIN-Test opcodes are exported as NOPs.
//   OP_NOP2 == OP_CHECKLOCKTIMEVERIFY (0xb1)
//   OP_NOP3 == OP_CHECKSEQUENCEVERIFY (0xb2)
//   OP_NOP4 == OP_CHECKTEMPLATEVERIFY (0xb3)
//   OP_NOP5 == OP_CHECKSIGFROMSTACK  (0xb4)
//   OP_NOP6 == OP_TXHASH             (0xb5)
//   OP_NOP7 == OP_TXFIELD            (0xb6)
//   OP_NOP8 == OP_SPLIT              (0xb7)
export const OP_NOP1 = 0xb0;
export const OP_NOP9 = 0xb8;
export const OP_NOP10 = 0xb9;

// ---------- Locktime ----------
export const OP_CHECKLOCKTIMEVERIFY = 0xb1;
export const OP_CHECKSEQUENCEVERIFY = 0xb2;

// ---------- Covenants & templates (DePIN-Test) ----------
export const OP_CHECKTEMPLATEVERIFY = 0xb3; // BIP 119
export const OP_CHECKSIGFROMSTACK = 0xb4;

// ---------- Transaction introspection (DePIN-Test) ----------
export const OP_TXHASH = 0xb5;
export const OP_TXFIELD = 0xb6;
export const OP_TXLOCKTIME = 0xc5;
export const OP_OUTPUTVALUE = 0xcc;
export const OP_OUTPUTSCRIPT = 0xcd;
export const OP_INPUTCOUNT = 0xd0;
export const OP_OUTPUTCOUNT = 0xd1;

// ---------- Asset introspection (DePIN-Test) ----------
export const OP_OUTPUTASSETFIELD = 0xce;
export const OP_INPUTASSETFIELD = 0xcf;
export const OP_XNA_ASSET = 0xc0;

// ---------- Reference inputs (DePIN-Test, NIP-017) ----------
export const OP_REFINPUTFIELD = 0xd2;
export const OP_REFINPUTASSETFIELD = 0xd3;
export const OP_REFINPUTCOUNT = 0xd4;

// ---------- Output auth commitment introspection (NIP-023) ----------
// Pushes the 32-byte AuthScript v1 commitment of a selected output's
// scriptPubKey. Symmetric to TXFIELD_AUTHSCRIPT_COMMITMENT for inputs;
// ignores any trailing OP_XNA_ASSET asset wrapper bytes.
export const OP_OUTPUTAUTHCOMMITMENT = 0xd5;

// ---------- Byte manipulation (DePIN-Test) ----------
export const OP_CAT = 0x7e;
export const OP_SPLIT = 0xb7;
export const OP_REVERSEBYTES = 0xbc;

// ---------- Selectors for OP_TXFIELD / OP_REFINPUTFIELD ----------
// Both opcodes share the same selector table (OP_TXFIELD on the spent UTXO,
// OP_REFINPUTFIELD on an output referenced via vrefin). Valid: 0x01..0x03.
export const TXFIELD_VALUE = 0x01;
export const TXFIELD_AUTHSCRIPT_COMMITMENT = 0x02;
export const TXFIELD_SCRIPTPUBKEY = 0x03;

// ---------- Bitmask selectors for OP_TXHASH ----------
// The selector is a single byte where each bit selects which transaction
// field to include in the double-SHA256. Selector 0x00 is invalid; any
// non-zero combination is valid. 0xff = all eight fields.
export const TXHASH_VERSION = 0x01;
export const TXHASH_LOCKTIME = 0x02;
export const TXHASH_INPUT_PREVOUTS = 0x04;
export const TXHASH_INPUT_SEQUENCES = 0x08;
export const TXHASH_OUTPUTS = 0x10;
export const TXHASH_CURRENT_PREVOUT = 0x20;
export const TXHASH_CURRENT_SEQUENCE = 0x40;
export const TXHASH_CURRENT_INDEX = 0x80;
export const TXHASH_ALL = 0xff;

// ---------- Selectors for OP_OUTPUTASSETFIELD / OP_INPUTASSETFIELD / OP_REFINPUTASSETFIELD ----------
// All three opcodes share the same selector table. Valid range: 0x01..0x07.
// Selector 0x05 is the boolean "has IPFS" flag; 0x06 is the IPFS hash
// payload; 0x07 is the asset operation type. (This matches the asset-op
// encoding in `src/assets/assets.cpp` and the NIP spec §3.1.)
export const ASSETFIELD_NAME = 0x01;
export const ASSETFIELD_AMOUNT = 0x02;
export const ASSETFIELD_UNITS = 0x03;
export const ASSETFIELD_REISSUABLE = 0x04;
export const ASSETFIELD_HAS_IPFS = 0x05;
export const ASSETFIELD_IPFS_HASH = 0x06;
export const ASSETFIELD_TYPE = 0x07;
