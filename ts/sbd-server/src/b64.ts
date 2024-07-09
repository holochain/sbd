import { fromUint8Array, toUint8Array } from 'js-base64';

/**
 * Convert to base64url representation.
 */
export function toB64Url(s: Uint8Array): string {
  return fromUint8Array(s)
    .replace(/\=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/**
 * Convert from base64url representation.
 */
export function fromB64Url(s: string): Uint8Array {
  return toUint8Array(s.replace(/\-/g, '+').replace(/\_/g, '/'));
}
