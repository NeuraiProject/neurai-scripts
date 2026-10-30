/**
 * NIP-054 vote lock: a wallet template (not part of the opcode) that holds a
 * role's owner token while it votes for a proposal.
 *
 * The holder sends the owner token, with the proposal hash H as its transfer
 * message, to the generic AuthScript v1 (NoAuth) address of this script:
 *
 *   OP_IF                                     execute, up to height T
 *     OP_1 OP_CHAINCONTEXT <T> OP_LESSTHANOREQUAL OP_VERIFY
 *     OP_SWAP OP_4 OP_INPUTFIELD <0x01 || C> OP_EQUALVERIFY
 *     OP_OUTPUTSCRIPT <return> OP_EQUAL
 *   OP_ELSE                                   give it back, after T
 *     OP_1 OP_CHAINCONTEXT <T> OP_GREATERTHAN OP_VERIFY
 *     OP_NIP OP_OUTPUTSCRIPT <return> OP_EQUAL
 *   OP_ENDIF
 *
 * Both branches send the token back to its owner (`return`, the full output
 * script). The execute branch also needs the custody, commitment C, at the
 * input it names. It must use OP_INPUTFIELD selector 04, the full
 * version-plus-commitment: selector 02 only reads the first 34 bytes of the
 * spent script, which a forged anyone-can-spend custody can match.
 */
export interface AssetAuthVoteLockParams {
    /** Expiry height of the proposal the vote is for. */
    T: number;
    /** 32-byte AuthScript commitment C of the custody, as in its scriptPubKey `OP_1 <C>` (hex or bytes). */
    custodyCommitment: string | Uint8Array;
    /** The output script that gives the owner token back to its holder (hex or bytes). */
    returnScriptPubKey: string | Uint8Array;
}
export declare function buildAssetAuthVoteLockScript(params: AssetAuthVoteLockParams): Uint8Array;
/**
 * Witness `args` of the execute branch: the index of the custody input and
 * the index of the output that returns the token.
 */
export declare function buildAssetAuthVoteExecuteArgs(params: {
    custodyInput: number;
    returnOutput: number;
}): Uint8Array[];
/** Witness `args` of the return branch, after T. */
export declare function buildAssetAuthVoteReturnArgs(params: {
    returnOutput: number;
}): Uint8Array[];
