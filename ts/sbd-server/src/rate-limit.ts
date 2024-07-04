export interface RateLimitResult {
  limitNanosPerByte: number;
  shouldBlock: boolean;
}

function nowNanos(now: number | bigint): bigint {
  if (typeof now === 'bigint') {
    return now;
  } else {
    const tmp: bigint = BigInt(now);
    return tmp * 1000000n;
  }
}

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
