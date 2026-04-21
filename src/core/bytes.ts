/**
 * Minimal byte helpers. A subset of what `neurai-create-transaction` exposes,
 * duplicated here to keep this package free of runtime coupling beyond its
 * declared `dependencies` field. All sizes are little-endian, per Neurai.
 */

export function ensureHex(hex: string, label = 'hex'): string {
  const normalized = String(hex || '').trim().toLowerCase();
  if (!/^[0-9a-f]*$/.test(normalized) || normalized.length % 2 !== 0) {
    throw new Error(`Invalid ${label}: expected even-length hex string`);
  }
  return normalized;
}

export function hexToBytes(hex: string): Uint8Array {
  const normalized = ensureHex(hex);
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    bytes[i / 2] = Number.parseInt(normalized.slice(i, i + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
