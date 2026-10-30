/**
 * NIP-054 P2AH custody policy (`OP_CHECKASSETAUTH`, AuthScript only).
 *
 * The policy is the witnessScript of a generic AuthScript v1 (NoAuth)
 * address. A spend of that address needs M of the N owner-token roles of the
 * list to approve it (G of them when an owner token held by the custody
 * leaves it):
 *
 *   policy:  <1> <M> <G> <role_1> ... <role_n> <n> OP_CHECKASSETAUTH
 *   witness: [0x00, <c>, <a>, <b>, <T>, policy]
 *
 * Build the four arguments with `buildAssetAuthArgs` and wrap them with
 * `buildAuthScriptWitnessNoAuth({ args, witnessScript: policy })`. A role
 * approves either by spending its owner token from P2PKH or a strict
 * AuthScript address with a SIGHASH_ALL signature (synchronous spend, every
 * argument 0), or by a vote (see `vote.ts` and `proposal.ts`).
 */
/** The only policy version defined by NIP-054. */
export declare const ASSETAUTH_POLICY_VERSION = 1;
/** Highest number of roles in one policy. */
export declare const ASSETAUTH_MAX_ROLES = 16;
export interface AssetAuthPolicy {
    /** Roles that must approve a spend. */
    M: number;
    /** Roles that must approve when an owner token held by the custody leaves it (M <= G). */
    G: number;
    /** Owner token names (`NAME!`, `&NAME!`). Any order: the script lists them sorted by bytes. */
    roles: string[];
}
export interface AssetAuthArgs {
    /** Proposal inputs: inputs 0..c-1 are committed by the proposal hash. */
    c: number;
    /** Proposal output prefix: outputs 0..a-1. */
    a: number;
    /** Proposal output suffix: the last b outputs. */
    b: number;
    /** Expiry height of the votes. */
    T: number;
}
export declare function buildAssetAuthPolicyScript(policy: AssetAuthPolicy): Uint8Array;
/** Inverse of `buildAssetAuthPolicyScript`; rejects any other script. */
export declare function parseAssetAuthPolicyScript(script: Uint8Array): AssetAuthPolicy;
/**
 * Witness `args` [<c>, <a>, <b>, <T>] for the custody input: minimal script
 * numbers, 0 as the empty element. All default to 0, the synchronous spend.
 */
export declare function buildAssetAuthArgs({ c, a, b, T }?: Partial<AssetAuthArgs>): Uint8Array[];
