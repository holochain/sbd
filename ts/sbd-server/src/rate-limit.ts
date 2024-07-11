import { DurableObject } from 'cloudflare:workers';

import * as common from './common.ts';

/**
 * `bytesReceived` call response type.
 */
export interface RateLimitResult {
  /**
   * How many nanos per byte this connection should be allowed to send.
   */
  limitNanosPerByte: number;

  /**
   * True if this connection has already breached its rate limit.
   */
  shouldBlock: boolean;
}

/**
 * If a classic number, milliseconds since epoch.
 * If a bigint, nanoseconds since epoch.
 */
function nowNanos(now: number | bigint): bigint {
  if (typeof now === 'bigint') {
    return now;
  } else {
    const tmp: bigint = BigInt(now);
    return tmp * 1000000n;
  }
}

/**
 * Ratelimit potentially multiple clients coming from the same ip address.
 */
export class RateLimit {
  map: { [pk: string]: bigint };
  limitNanosPerByte: bigint;
  burst: bigint;

  constructor(limitNanosPerByte: number, burst: number) {
    this.map = {};
    this.limitNanosPerByte = BigInt(limitNanosPerByte);
    this.burst = this.limitNanosPerByte * BigInt(burst);
  }

  /**
   * Clear out any connections older that 10s in the past.
   *
   * - now: if now is a number, it is milliseconds since epoch
   *        if now is a bigint, it is nanoseconds since epoch
   */
  prune(now: number | bigint) {
    const nowNs = nowNanos(now);

    const newMap: { [pk: string]: bigint } = {};

    for (const pk in this.map) {
      const cur = this.map[pk];
      if (nowNs <= cur || nowNs - cur < 10000000000n) {
        newMap[pk] = cur;
      }
    }

    this.map = newMap;
  }

  /**
   * Log a number of bytes received from a single pubKey (connection).
   * Return a bitrate limit this connection should be following, and
   * whether that ip has already breached the limit.
   *
   * - now: if now is a number, it is milliseconds since epoch
   *        if now is a bigint, it is nanoseconds since epoch
   */
  bytesReceived(
    now: number | bigint,
    pk: string,
    bytes: number,
  ): RateLimitResult {
    this.prune(now);

    const nowNs = nowNanos(now);

    const rateAdd = BigInt(bytes) * this.limitNanosPerByte;

    if (!(pk in this.map)) {
      this.map[pk] = nowNs;
    }

    let cur = this.map[pk];

    if (nowNs > cur) {
      cur = nowNs;
    }

    cur += rateAdd;

    this.map[pk] = cur;

    const nextActionInNanos = cur - nowNs;

    const shouldBlock = nextActionInNanos > this.burst;

    const nodeCount: bigint = BigInt(Object.keys(this.map).length);
    const limitNanosPerByte = Number(this.limitNanosPerByte * nodeCount);

    return { limitNanosPerByte, shouldBlock };
  }
}

/**
 * "RATE_LIMIT" durable object.
 * This is a thin wrapper around the "RateLimit" class.
 */
export class DoRateLimit extends DurableObject {
  ctx: DurableObjectState;
  env: common.Env;
  rl: RateLimit;

  constructor(ctx: DurableObjectState, env: common.Env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
    this.rl = new RateLimit(common.LIMIT_NANOS_PER_BYTE, 16 * 16 * 1024);
  }

  async bytesReceived(
    now: number,
    pk: string,
    bytes: number,
  ): Promise<RateLimitResult> {
    return this.rl.bytesReceived(now, pk, bytes);
  }
}
