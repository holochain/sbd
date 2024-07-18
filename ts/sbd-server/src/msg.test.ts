import { describe, expect, assert, it, beforeAll, afterAll } from 'vitest';
import {
  Msg,
  MsgLbrt,
  MsgLidl,
  MsgAreq,
  MsgAres,
  MsgSrdy,
  MsgKeep,
  MsgNone,
  MsgForward,
} from './msg.ts';
import * as common from './common.ts';

describe('Msg', () => {
  it('lbrt', async () => {
    const orig = new MsgLbrt(42);
    expect(orig.type()).equals('lbrt');
    expect(orig.limit()).equals(42);
    const parsed = Msg.parse(orig.encoded());
    expect(parsed.type()).equals('lbrt');
    if (parsed instanceof MsgLbrt) {
      expect(parsed.limit()).equals(42);
    } else {
      throw 'invalid type';
    }
  });

  it('lidl', async () => {
    const orig = new MsgLidl(42);
    expect(orig.type()).equals('lidl');
    expect(orig.limit()).equals(42);
    const parsed = Msg.parse(orig.encoded());
    expect(parsed.type()).equals('lidl');
    if (parsed instanceof MsgLidl) {
      expect(parsed.limit()).equals(42);
    } else {
      throw 'invalid type';
    }
  });

  it('areq', async () => {
    const ononce = new Uint8Array([
      1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1,
      2, 3, 4, 5, 6, 7, 8,
    ]);
    const orig = new MsgAreq(ononce);
    expect(orig.type()).equals('areq');
    expect(orig.nonce()).deep.equals(ononce);
    const parsed = Msg.parse(orig.encoded());
    expect(parsed.type()).equals('areq');
    if (parsed instanceof MsgAreq) {
      expect(parsed.nonce()).deep.equals(ononce);
    } else {
      throw 'invalid type';
    }
  });

  it('ares', async () => {
    const osig = new Uint8Array([
      1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1,
      2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2,
      3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
    ]);
    const orig = new MsgAres(osig);
    expect(orig.type()).equals('ares');
    expect(orig.signature()).deep.equals(osig);
    const parsed = Msg.parse(orig.encoded());
    expect(parsed.type()).equals('ares');
    if (parsed instanceof MsgAres) {
      expect(parsed.signature()).deep.equals(osig);
    } else {
      throw 'invalid type';
    }
  });

  it('srdy', async () => {
    const orig = new MsgSrdy();
    expect(orig.type()).equals('srdy');
    const parsed = Msg.parse(orig.encoded());
    expect(parsed.type()).equals('srdy');
    if (!(parsed instanceof MsgSrdy)) {
      throw 'invalid type';
    }
  });

  it('keep', async () => {
    const orig = new MsgKeep();
    expect(orig.type()).equals('keep');
    const parsed = Msg.parse(orig.encoded());
    expect(parsed.type()).equals('keep');
    if (!(parsed instanceof MsgKeep)) {
      throw 'invalid type';
    }
  });

  it('none', async () => {
    const unknown = new Uint8Array([
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 23, 23, 23, 23, 0, 1, 0, 2, 0, 3, 0, 4,
    ]);
    const parsed = Msg.parse(unknown);
    expect(parsed.type()).equals('none');
    if (!(parsed instanceof MsgNone)) {
      throw 'invalid type';
    }
  });

  it('forward', async () => {
    const opk = new Uint8Array([
      1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1,
      2, 3, 4, 5, 6, 7, 8,
    ]);
    const odata = new Uint8Array([1, 2, 3, 4]);
    const orig = MsgForward.build(opk, odata);
    expect(orig.type()).equals('forward');
    expect(orig.pubKey()).deep.equals(opk);
    expect(orig.payload()).deep.equals(odata);
    const parsed = Msg.parse(orig.encoded());
    expect(parsed.type()).equals('forward');
    if (parsed instanceof MsgForward) {
      expect(parsed.pubKey()).deep.equals(opk);
      expect(parsed.payload()).deep.equals(odata);
    } else {
      throw 'invalid type';
    }
  });
});
