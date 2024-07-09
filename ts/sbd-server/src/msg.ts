import { ed } from './ed.ts';
import { err } from './err.ts';
import { toB64Url, fromB64Url } from './b64.ts';

/**
 * Byte-by-byte comparison of Uint8Array types.
 */
function cmp(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  for (let i = 0; i < a.byteLength; ++i) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/**
 * 28 zeroes indicate a "command" type message.
 */
const CMD: Uint8Array = new Uint8Array(28);

/**
 * Limit bitrate.
 */
export const MSG_T_LBRT: string = 'lbrt';
const MSG_B_LBRT: Uint8Array = new TextEncoder().encode(MSG_T_LBRT);

/**
 * Idle limit milliseconds.
 */
export const MSG_T_LIDL: string = 'lidl';
const MSG_B_LIDL: Uint8Array = new TextEncoder().encode(MSG_T_LIDL);

/**
 * Server initiated handshake request.
 */
export const MSG_T_AREQ: string = 'areq';
const MSG_B_AREQ: Uint8Array = new TextEncoder().encode(MSG_T_AREQ);

/**
 * Client handshake response.
 */
export const MSG_T_ARES: string = 'ares';
const MSG_B_ARES: Uint8Array = new TextEncoder().encode(MSG_T_ARES);

/**
 * Handshake success.
 */
export const MSG_T_SRDY: string = 'srdy';
const MSG_B_SRDY: Uint8Array = new TextEncoder().encode(MSG_T_SRDY);

/**
 * Client-sent keepalive.
 */
export const MSG_T_KEEP: string = 'keep';
const MSG_B_KEEP: Uint8Array = new TextEncoder().encode(MSG_T_KEEP);

/**
 * "Unknown message" to be used for compatibility with future clients.
 */
export const MSG_T_NONE: string = 'none';
const MSG_B_NONE: Uint8Array = new TextEncoder().encode(MSG_T_NONE);

/**
 * This message was not a command, it was a forward.
 * The first 32 bytes are the pubkey to which we will forward the data.
 * (There's no binary Uint8Array version of this, it's just a flag).
 */
export const MSG_T_FORWARD: string = 'forward';

/**
 * Base message abstract class.
 */
export class Msg {
  #bytes: Uint8Array;
  #type: string;

  constructor(bytes: Uint8Array, type: string) {
    this.#bytes = bytes;
    this.#type = type;
  }

  /**
   * Parse a message byte array into the correct message subtype.
   */
  static parse(
    bytes: Uint8Array,
  ): MsgLbrt | MsgLidl | MsgAreq | MsgAres | MsgSrdy | MsgKeep {
    if (bytes.byteLength < 32) {
      throw err(`invalid msg length ${bytes.byteLength}`, 400);
    }

    if (cmp(bytes.subarray(0, 28), CMD)) {
      if (cmp(bytes.subarray(28, 32), MSG_B_LBRT)) {
        if (bytes.byteLength !== 32 + 4) {
          throw err(
            `invalid lbrt msg length, expected 36, got: ${bytes.byteLength}`,
            400,
          );
        }
        const limit = new DataView(bytes.buffer).getInt32(32, false);
        return new MsgLbrt(limit);
      } else if (cmp(bytes.subarray(28, 32), MSG_B_LIDL)) {
        if (bytes.byteLength !== 32 + 4) {
          throw err(
            `invalid lidl msg length, expected 36, got: ${bytes.byteLength}`,
            400,
          );
        }
        const limit = new DataView(bytes.buffer).getInt32(32, false);
        return new MsgLidl(limit);
      } else if (cmp(bytes.subarray(28, 32), MSG_B_AREQ)) {
        if (bytes.byteLength !== 32 + 32) {
          throw err(
            `invalid areq msg length, expected 64, got: ${bytes.byteLength}`,
            400,
          );
        }
        const nonce = bytes.slice(32);
        return new MsgAreq(nonce);
      } else if (cmp(bytes.subarray(28, 32), MSG_B_ARES)) {
        if (bytes.byteLength !== 32 + 64) {
          throw err(
            `invalid ares msg length, expected 96, got: ${bytes.byteLength}`,
            400,
          );
        }
        const signature = bytes.slice(32);
        return new MsgAres(signature);
      } else if (cmp(bytes.subarray(28, 32), MSG_B_SRDY)) {
        if (bytes.byteLength !== 32) {
          throw err(
            `invalid srdy msg length, expected 32, got: ${bytes.byteLength}`,
            400,
          );
        }
        return new MsgSrdy();
      } else if (cmp(bytes.subarray(28, 32), MSG_B_KEEP)) {
        if (bytes.byteLength !== 32) {
          throw err(
            `invalid keep msg length, expected 32, got: ${bytes.byteLength}`,
            400,
          );
        }
        return new MsgKeep();
      } else {
        return new MsgNone();
      }
    } else {
      return new MsgForward(bytes);
    }
  }

  /**
   * Return the `MSG_T_` type of this message.
   */
  type(): string {
    return this.#type;
  }

  /**
   * Get the encoded bytes of this message.
   */
  encoded(): Uint8Array {
    return this.#bytes;
  }
}

/**
 * Limit bitrate.
 */
export class MsgLbrt extends Msg {
  #limit: number;

  constructor(limit: number) {
    const bytes = new Uint8Array(32 + 4);
    bytes.set(CMD, 0);
    bytes.set(MSG_B_LBRT, 28);
    new DataView(bytes.buffer).setInt32(32, limit, false);

    super(bytes, MSG_T_LBRT);

    this.#limit = limit;
  }

  /**
   * Get the "nanoseconds per byte" bitrate limit.
   */
  limit(): number {
    return this.#limit;
  }
}

/**
 * Idle limit milliseconds.
 */
export class MsgLidl extends Msg {
  #limit: number;

  constructor(limit: number) {
    const bytes = new Uint8Array(32 + 4);
    bytes.set(CMD, 0);
    bytes.set(MSG_B_LIDL, 28);
    new DataView(bytes.buffer).setInt32(32, limit, false);

    super(bytes, MSG_T_LIDL);

    this.#limit = limit;
  }

  /**
   * Get the millisecond count this connection can idle without being closed.
   */
  limit(): number {
    return this.#limit;
  }
}

/**
 * Server initiated handshake request.
 */
export class MsgAreq extends Msg {
  #nonce: Uint8Array;

  constructor(nonce: Uint8Array) {
    const bytes = new Uint8Array(32 + 32);
    bytes.set(CMD, 0);
    bytes.set(MSG_B_AREQ, 28);
    bytes.set(nonce, 32);

    super(bytes, MSG_T_AREQ);

    this.#nonce = nonce;
  }

  /**
   * A nonce for the client to sign.
   */
  nonce(): Uint8Array {
    return this.#nonce;
  }
}

/**
 * Client handshake response.
 */
export class MsgAres extends Msg {
  #signature: Uint8Array;

  constructor(signature: Uint8Array) {
    const bytes = new Uint8Array(32 + 64);
    bytes.set(CMD, 0);
    bytes.set(MSG_B_ARES, 28);
    bytes.set(signature, 32);

    super(bytes, MSG_T_ARES);

    this.#signature = signature;
  }

  /**
   * A signature over the nonce bytes the server had sent.
   */
  signature(): Uint8Array {
    return this.#signature;
  }
}

/**
 * Handshake success.
 */
export class MsgSrdy extends Msg {
  constructor() {
    const bytes = new Uint8Array(32);
    bytes.set(CMD, 0);
    bytes.set(MSG_B_SRDY, 28);

    super(bytes, MSG_T_SRDY);
  }
}

/**
 * Client-sent keepalive.
 */
export class MsgKeep extends Msg {
  constructor() {
    const bytes = new Uint8Array(32);
    bytes.set(CMD, 0);
    bytes.set(MSG_B_KEEP, 28);

    super(bytes, MSG_T_KEEP);
  }
}

/**
 * "Unknown message" to be used for compatibility with future clients.
 */
export class MsgNone extends Msg {
  constructor() {
    const bytes = new Uint8Array(32);
    bytes.set(CMD, 0);
    bytes.set(MSG_B_NONE, 28);

    super(bytes, MSG_T_NONE);
  }
}

/**
 * This message is not a command, it is a forward.
 * The first 32 bytes are the pubkey to which we will forward the data.
 */
export class MsgForward extends Msg {
  constructor(bytes: Uint8Array) {
    super(bytes, MSG_T_FORWARD);
  }

  /**
   * Construct a forward message from parts.
   */
  static build(pubKey: Uint8Array, payload: Uint8Array): MsgForward {
    if (pubKey.byteLength !== 32) {
      throw err(
        `invalid pubKey length, expected 32, got: ${pubKey.byteLength}`,
        400,
      );
    }
    const bytes = new Uint8Array(32 + payload.byteLength);
    bytes.set(pubKey, 0);
    bytes.set(payload, 32);

    return new MsgForward(bytes);
  }

  /**
   * Get a subarray reference to the pubkey portion of this message.
   */
  pubKey(): Uint8Array {
    return this.encoded().subarray(0, 32);
  }

  /**
   * Get a subarray reference to the payload portion of this message.
   */
  payload(): Uint8Array {
    return this.encoded().subarray(32);
  }
}
