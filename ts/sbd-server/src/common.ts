import { fromUint8Array, toUint8Array } from 'js-base64';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
export { ed };

/**
 * How long to wait ahead of "now" to batch up message sends.
 * Note, we're setting this to zero which will try to send queued messages
 * as fast as possible. This doesn't mean messages won't be queued/batched,
 * since there will be a delay between requesting an alarm and when it
 * is actually invoked + however long it takes to actually run.
 */
export const BATCH_DUR_MS = 0;

/**
 * How many nanoseconds of rate limiting quota should be burned by a single
 * byte sent through the system. Higher numbers mean slower rate limiting.
 */
export const LIMIT_NANOS_PER_BYTE = 8000;

/**
 * How many nanoseconds of rate limiting burst graceperiod is allowed
 */
export const LIMIT_NANOS_BURST = LIMIT_NANOS_PER_BYTE * 16 * 16 * 1024;

/**
 * Milliseconds connections are allowed to remain idle before being closed.
 */
export const LIMIT_IDLE_MILLIS = 10000;

/**
 * Max message size.
 */
export const MAX_MESSAGE_BYTES = 20000;

/*
/ **
 * Cloudflare worker environment objects.
 * /
export interface EnvExplicit {
  SBD_COORDINATION: KVNamespace;
  SIGNAL: DurableObjectNamespace;
  RATE_LIMIT: DurableObjectNamespace;
}

/ **
 * Cloudflare worker environment variables.
 * /
export interface EnvVars {
  [index: string]: string;
}

/ **
 * Combined Cloudflare Env type.
 * /
export type Env = EnvExplicit & EnvVars;
*/

/**
 * Mixin to allow errors with status codes.
 */
export interface AddStatus {
  status: number;
}

/**
 * Error type with a status code.
 */
export type StatusError = Error & AddStatus;

/**
 * Adds a 'status' property to ts Error type.
 * If not specified will be set to 500.
 * Allows altering the http or ws error status for responses.
 * In the case of a websocket error, the http status code
 * will be added to 4000 for user-specified error codes.
 */
export function err(e: string, s?: number): StatusError {
  const out: any = new Error(e);
  out.status = s || 500;
  return out;
}

/**
 * Seconds since epoch timestamp.
 */
export function timestamp(): number {
  return (Date.now() / 1000) | 0;
}

/**
 * Pull pubKey string and bytes from the url path.
 */
export function parsePubKey(path: string): {
  pubKeyStr: string;
  pubKeyBytes: Uint8Array;
} {
  const parts: Array<string> = path.split('/');

  if (parts.length !== 2) {
    throw err('expected single pubKey item on path', 400);
  }

  const pubKeyStr = parts[1];

  const pubKeyBytes = fromB64Url(parts[1]);

  if (pubKeyBytes.length !== 32) {
    throw err('invalid pubKey length', 400);
  }

  return { pubKeyStr, pubKeyBytes };
}

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
