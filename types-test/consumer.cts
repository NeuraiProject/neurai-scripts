// CommonJS consumer: resolves the `require` condition (dist/index.d.cts).
// Every value export is used, so a missing declaration fails to compile.
import s = require("@neuraiproject/neurai-scripts");

export const values = [
  s.AUTHSCRIPT_LEGACY, s.AUTHSCRIPT_NOAUTH, s.AUTHSCRIPT_PQ, s.AUTHSCRIPT_REF,
  s.DEFAULT_PQ_TXHASH_SELECTOR, s.MULTISIG_MAX_PUBKEYS, s.NULLDATA_STANDARD_MAX_SIZE, s.PQ_PUBKEY_PREFIX,
  s.STRICT_PQ_PUBKEY_LENGTH, s.ScriptBuilder, s.buildAuthScriptWitnessLegacy, s.buildAuthScriptWitnessNoAuth,
  s.buildAuthScriptWitnessPQ, s.buildAuthScriptWitnessRef, s.buildCancelScriptSig, s.buildCancelScriptSigHex,
  s.buildCancelScriptSigPQ, s.buildCancelScriptSigPQHex, s.buildCancelWitnessStack, s.buildCancelWitnessStackPQ,
  s.buildFillScriptSig, s.buildFillScriptSigHex, s.buildFillWitnessStack, s.buildPartialFillScript,
  s.buildPartialFillScriptHex, s.buildPartialFillScriptPQ, s.buildPartialFillScriptPQHex, s.buildStrictWitnessECDSA,
  s.buildStrictWitnessPQ, s.bytesEqual, s.bytesToHex, s.concatBytes,
  s.encodeAuthScriptScriptPubKey, s.encodeMultisigRedeemScript, s.encodeMultisigRedeemScriptHex, s.encodeNullDataScript,
  s.encodeP2PKHScriptPubKey, s.encodeP2SHScriptPubKey, s.encodeP2WPKHScriptPubKey, s.encodeP2WSHScriptPubKey,
  s.encodeScriptNum, s.encodeSellerScriptPubKey, s.ensureHex, s.hexToBytes,
  s.isPartialFillScriptPQ, s.opcodes, s.parsePartialFillScript, s.parsePartialFillScriptPQ,
  s.pushBytes, s.pushHex, s.pushInt, s.splitAssetWrappedScriptPubKey,
];
export const seller: s.SellerScriptPubKey = s.encodeSellerScriptPubKey("tpq1z5age5p2v5q9w6qzadkjp4yep8gpr56q6mzd4fu6eus8ntulul6vq3q07pc");
export const version: s.AuthScriptWitnessVersion | undefined = seller.witnessVersion;
export type Kind = s.SellerAddressKind;
