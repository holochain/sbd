import { ed } from './ed.ts';
import { err } from './err.ts';
import { toB64Url, fromB64Url } from './b64.ts';

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

const CMD: Uint8Array = new Uint8Array(28);

export const MSG_T_LBRT: string = 'lbrt';
const MSG_B_LBRT: Uint8Array = new TextEncoder().encode(MSG_T_LBRT);

export const MSG_T_LIDL: string = 'lidl';
const MSG_B_LIDL: Uint8Array = new TextEncoder().encode(MSG_T_LIDL);

export const MSG_T_AREQ: string = 'areq';
const MSG_B_AREQ: Uint8Array = new TextEncoder().encode(MSG_T_AREQ);

export const MSG_T_ARES: string = 'ares';
const MSG_B_ARES: Uint8Array = new TextEncoder().encode(MSG_T_ARES);

export const MSG_T_SRDY: string = 'srdy';
const MSG_B_SRDY: Uint8Array = new TextEncoder().encode(MSG_T_SRDY);

export const MSG_T_KEEP: string = 'keep';
const MSG_B_KEEP: Uint8Array = new TextEncoder().encode(MSG_T_KEEP);

export const MSG_T_NONE: string = 'none';
const MSG_B_NONE: Uint8Array = new TextEncoder().encode(MSG_T_NONE);

export const MSG_T_FORWARD: string = 'forward';

export class Msg {
  #bytes: Uint8Array;
  #type: string;

  constructor(bytes: Uint8Array, type: string) {
    this.#bytes = bytes;
    this.#type = type;
  }

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

  type(): string {
    return this.#type;
  }

  encoded(): Uint8Array {
    return this.#bytes;
  }
}

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

  limit(): number {
    return this.#limit;
  }
}

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

  limit(): number {
    return this.#limit;
  }
}

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

  nonce(): Uint8Array {
    return this.#nonce;
  }
}

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

  signature(): Uint8Array {
    return this.#signature;
  }
}

export class MsgSrdy extends Msg {
  constructor() {
    const bytes = new Uint8Array(32);
    bytes.set(CMD, 0);
    bytes.set(MSG_B_SRDY, 28);

    super(bytes, MSG_T_SRDY);
  }
}

export class MsgKeep extends Msg {
  constructor() {
    const bytes = new Uint8Array(32);
    bytes.set(CMD, 0);
    bytes.set(MSG_B_KEEP, 28);

    super(bytes, MSG_T_KEEP);
  }
}

export class MsgNone extends Msg {
  constructor() {
    const bytes = new Uint8Array(32);
    bytes.set(CMD, 0);
    bytes.set(MSG_B_NONE, 28);

    super(bytes, MSG_T_NONE);
  }
}

export class MsgForward extends Msg {
  constructor(bytes: Uint8Array) {
    super(bytes, MSG_T_FORWARD);
  }

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

  pubKey(): Uint8Array {
    return this.encoded().subarray(0, 32);
  }

  payload(): Uint8Array {
    return this.encoded().subarray(32);
  }
}
