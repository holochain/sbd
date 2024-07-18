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

interface State {
  map: { [pk: string]: bigint };
  next: bigint;
}

enum BlockCheck {
  Unchecked,
  Unblocked,
  Blocked,
}

const BLOCKED: RateLimitResult = {
  limitNanosPerByte: Number.MAX_SAFE_INTEGER,
  shouldBlock: true,
};

/**
 * "RATE_LIMIT" durable object.
 * This is a thin wrapper around the "RateLimit" class.
 */
export class DoRateLimit extends DurableObject {
  ctx: DurableObjectState;
  env: Env;
  lastUnblockCheck: number;
  blockCheck: BlockCheck;
  state: State;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);

    this.ctx = ctx;
    this.env = env;

    this.lastUnblockCheck = 0;
    this.blockCheck = BlockCheck.Unchecked;

    // Note, we're making an explicit decision to NOT store this state
    // in either the DO transactional storage or KV store.
    // It would cost a lot to keep it updated enough to be useful,
    // and we are doing our own memory eviction after 10 seconds anyways.
    // Assuming we are not evicted within 10 seconds (docs are vague),
    // this will work as well as trying to store it anywhere.
    this.state = { map: {}, next: 0n };
  }

  /**
   * Update block state from KV for this IP if it is correct to do so.
   */
  async checkBlockState(ip: string) {
    if (this.blockCheck === BlockCheck.Unblocked) {
      // do not check the KV if we are currently unblocked
      return;
    } else if (this.blockCheck === BlockCheck.Blocked) {
      if (Date.now() - this.lastUnblockCheck < 1000 * 60 * 2) {
        // if we are blocked, and have checked within the past 2 minutes
        // don't bother checking again
        return;
      }
      this.lastUnblockCheck = Date.now();
    }

    // if we made it past the above checks, go ahead and check the kv
    const block = await this.env.SBD_COORDINATION.get(`block:${ip}`, {
      type: 'json',
    });

    // if we get a `true` back from the kv, mark blocked
    // otherwise mark unblocked
    if (typeof block === 'boolean' && block) {
      this.blockCheck = BlockCheck.Blocked;
    } else {
      this.blockCheck = BlockCheck.Unblocked;
    }
  }

  /**
   * Log a number of bytes received from a single pubKey (connection).
   * Return a bitrate limit this connection should be following, and
   * whether that ip has already breached the limit.
   *
   * - now: milliseconds since epoch
   */
  async bytesReceived(
    now: number,
    ip: string,
    pk: string,
    bytes: number,
  ): Promise<RateLimitResult> {
    return await this.ctx.blockConcurrencyWhile(async () => {
      await this.checkBlockState(ip);

      if (this.blockCheck === BlockCheck.Blocked) {
        return BLOCKED;
      }

      const nowN = BigInt(now) * 1000000n;

      // prune the map

      const newMap: { [pk: string]: bigint } = {};

      for (const pk in this.state.map) {
        const last = this.state.map[pk];
        // keep if it is newer than 10 seconds
        if (last >= nowN - 10000000000n) {
          newMap[pk] = last;
        }
      }

      this.state.map = newMap;

      // log the pk last access time

      this.state.map[pk] = nowN;

      // log the additional bytes

      if (this.state.next < nowN) {
        this.state.next = nowN;
      }

      const rateAdd = BigInt(bytes) * BigInt(common.LIMIT_NANOS_PER_BYTE);

      this.state.next += rateAdd;

      const shouldBlock = this.state.next - nowN > common.LIMIT_NANOS_BURST;
      const limitNanosPerByte =
        common.LIMIT_NANOS_PER_BYTE * Object.keys(this.state.map).length;

      if (shouldBlock) {
        this.blockCheck = BlockCheck.Blocked;
        await this.env.SBD_COORDINATION.put(`block:${ip}`, 'true', {
          expirationTtl: 60 * 10,
        });
        return BLOCKED;
      }

      return { limitNanosPerByte, shouldBlock };
    });
  }
}
