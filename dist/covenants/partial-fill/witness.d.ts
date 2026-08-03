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
 * witness.
 */
/**
 * Witness `args` for the public fill branches. Same semantics and
 * validations as `buildFillScriptSig`.
 */
export declare function buildFillWitnessStack(amount: bigint, total: bigint): Uint8Array[];
/**
 * Witness `args` for the seller's ECDSA cancel branch. Same semantics and
 * validations as `buildCancelScriptSig`.
 */
export declare function buildCancelWitnessStack(signatureDer: Uint8Array, pubKey: Uint8Array): Uint8Array[];
/**
 * Witness `args` for the seller's PQ (ML-DSA-44) cancel branch. Same
 * semantics and validations as `buildCancelScriptSigPQ`.
 */
export declare function buildCancelWitnessStackPQ(sigPQ: Uint8Array, pubKey: Uint8Array): Uint8Array[];
