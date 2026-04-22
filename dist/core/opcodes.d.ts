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
export declare const OP_0 = 0;
export declare const OP_FALSE = 0;
export declare const OP_PUSHDATA1 = 76;
export declare const OP_PUSHDATA2 = 77;
export declare const OP_PUSHDATA4 = 78;
export declare const OP_1NEGATE = 79;
export declare const OP_RESERVED = 80;
export declare const OP_1 = 81;
export declare const OP_TRUE = 81;
export declare const OP_2 = 82;
export declare const OP_3 = 83;
export declare const OP_4 = 84;
export declare const OP_5 = 85;
export declare const OP_6 = 86;
export declare const OP_7 = 87;
export declare const OP_8 = 88;
export declare const OP_9 = 89;
export declare const OP_10 = 90;
export declare const OP_11 = 91;
export declare const OP_12 = 92;
export declare const OP_13 = 93;
export declare const OP_14 = 94;
export declare const OP_15 = 95;
export declare const OP_16 = 96;
export declare const OP_NOP = 97;
export declare const OP_IF = 99;
export declare const OP_NOTIF = 100;
export declare const OP_ELSE = 103;
export declare const OP_ENDIF = 104;
export declare const OP_VERIFY = 105;
export declare const OP_RETURN = 106;
export declare const OP_TOALTSTACK = 107;
export declare const OP_FROMALTSTACK = 108;
export declare const OP_2DROP = 109;
export declare const OP_2DUP = 110;
export declare const OP_3DUP = 111;
export declare const OP_2OVER = 112;
export declare const OP_2ROT = 113;
export declare const OP_2SWAP = 114;
export declare const OP_IFDUP = 115;
export declare const OP_DEPTH = 116;
export declare const OP_DROP = 117;
export declare const OP_DUP = 118;
export declare const OP_NIP = 119;
export declare const OP_OVER = 120;
export declare const OP_PICK = 121;
export declare const OP_ROLL = 122;
export declare const OP_ROT = 123;
export declare const OP_SWAP = 124;
export declare const OP_TUCK = 125;
export declare const OP_SIZE = 130;
export declare const OP_EQUAL = 135;
export declare const OP_EQUALVERIFY = 136;
export declare const OP_1ADD = 139;
export declare const OP_1SUB = 140;
export declare const OP_NEGATE = 143;
export declare const OP_ABS = 144;
export declare const OP_NOT = 145;
export declare const OP_0NOTEQUAL = 146;
export declare const OP_ADD = 147;
export declare const OP_SUB = 148;
export declare const OP_MUL = 149;
export declare const OP_DIV = 150;
export declare const OP_MOD = 151;
export declare const OP_BOOLAND = 154;
export declare const OP_BOOLOR = 155;
export declare const OP_NUMEQUAL = 156;
export declare const OP_NUMEQUALVERIFY = 157;
export declare const OP_NUMNOTEQUAL = 158;
export declare const OP_LESSTHAN = 159;
export declare const OP_GREATERTHAN = 160;
export declare const OP_LESSTHANOREQUAL = 161;
export declare const OP_GREATERTHANOREQUAL = 162;
export declare const OP_MIN = 163;
export declare const OP_MAX = 164;
export declare const OP_WITHIN = 165;
export declare const OP_RIPEMD160 = 166;
export declare const OP_SHA1 = 167;
export declare const OP_SHA256 = 168;
export declare const OP_HASH160 = 169;
export declare const OP_HASH256 = 170;
export declare const OP_CODESEPARATOR = 171;
export declare const OP_CHECKSIG = 172;
export declare const OP_CHECKSIGVERIFY = 173;
export declare const OP_CHECKMULTISIG = 174;
export declare const OP_CHECKMULTISIGVERIFY = 175;
export declare const OP_NOP1 = 176;
export declare const OP_NOP9 = 184;
export declare const OP_NOP10 = 185;
export declare const OP_CHECKLOCKTIMEVERIFY = 177;
export declare const OP_CHECKSEQUENCEVERIFY = 178;
export declare const OP_CHECKTEMPLATEVERIFY = 179;
export declare const OP_CHECKSIGFROMSTACK = 180;
export declare const OP_TXHASH = 181;
export declare const OP_TXFIELD = 182;
export declare const OP_TXLOCKTIME = 197;
export declare const OP_OUTPUTVALUE = 204;
export declare const OP_OUTPUTSCRIPT = 205;
export declare const OP_INPUTCOUNT = 208;
export declare const OP_OUTPUTCOUNT = 209;
export declare const OP_OUTPUTASSETFIELD = 206;
export declare const OP_INPUTASSETFIELD = 207;
export declare const OP_XNA_ASSET = 192;
export declare const OP_REFINPUTFIELD = 210;
export declare const OP_REFINPUTASSETFIELD = 211;
export declare const OP_REFINPUTCOUNT = 212;
export declare const OP_OUTPUTAUTHCOMMITMENT = 213;
export declare const OP_CAT = 126;
export declare const OP_SPLIT = 183;
export declare const OP_REVERSEBYTES = 188;
export declare const TXFIELD_VALUE = 1;
export declare const TXFIELD_AUTHSCRIPT_COMMITMENT = 2;
export declare const TXFIELD_SCRIPTPUBKEY = 3;
export declare const TXHASH_VERSION = 1;
export declare const TXHASH_LOCKTIME = 2;
export declare const TXHASH_INPUT_PREVOUTS = 4;
export declare const TXHASH_INPUT_SEQUENCES = 8;
export declare const TXHASH_OUTPUTS = 16;
export declare const TXHASH_CURRENT_PREVOUT = 32;
export declare const TXHASH_CURRENT_SEQUENCE = 64;
export declare const TXHASH_CURRENT_INDEX = 128;
export declare const TXHASH_ALL = 255;
export declare const ASSETFIELD_NAME = 1;
export declare const ASSETFIELD_AMOUNT = 2;
export declare const ASSETFIELD_UNITS = 3;
export declare const ASSETFIELD_REISSUABLE = 4;
export declare const ASSETFIELD_HAS_IPFS = 5;
export declare const ASSETFIELD_IPFS_HASH = 6;
export declare const ASSETFIELD_TYPE = 7;
