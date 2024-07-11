import { unstable_dev } from 'wrangler';
import type { UnstableDevWorker } from 'wrangler';
import { describe, expect, assert, it, beforeEach, afterEach } from 'vitest';
import { RateLimit } from './rate-limit.ts';

describe('RateLimit', () => {
  let worker: UnstableDevWorker;

  beforeEach(async () => {
    worker = await unstable_dev('./src/test-rate-limit-index.ts', {
      experimental: { disableExperimentalWarning: true },
    });
  });

  afterEach(async () => {
    await worker.stop();
  });

  it('sanity', async () => {});

  /*
  it('check multi-node rate limit', async () => {
    const addr1 = 'yada1';
    const addr2 = 'yada2';

    let now = 100;

    const rate = new RateLimit(8000, 16 * 16 * 1024);

    let limitNanosPerByte = null;

    ({ limitNanosPerByte } = rate.bytesReceived(now, addr1, 1));

    expect(limitNanosPerByte).equals(8000);

    ({ limitNanosPerByte } = rate.bytesReceived(now, addr2, 1));

    expect(limitNanosPerByte).equals(16000);

    now += 20000;

    ({ limitNanosPerByte } = rate.bytesReceived(now, addr2, 1));
    expect(limitNanosPerByte).equals(8000);
  });

  it('1 to 1 and prune', async () => {
    const addr = 'yada';

    let now = 100n;
    let shouldBlock = null;

    const rate = new RateLimit(1, 1);

    // should always be ok when advancing with time
    for (let i = 0; i < 10; ++i) {
      now += 1n;

      ({ shouldBlock } = rate.bytesReceived(now, addr, 1));

      assert(!shouldBlock);
    }

    // but one more without a time advance fails
    ({ shouldBlock } = rate.bytesReceived(now, addr, 1));
    assert(shouldBlock);

    now += 1n;

    // make sure prune doesn't prune it yet
    rate.prune(now);
    ({ shouldBlock } = rate.bytesReceived(now, addr, 1));
    assert(shouldBlock);

    now += 1n;

    // make sure prune doesn't prune it even after 10 seconds
    rate.prune(now + 10000000000n);
    ({ shouldBlock } = rate.bytesReceived(now, addr, 1));
    assert(shouldBlock);

    now += 1n;

    // but it *will* after 10 seconds + 1 nanosecond
    rate.prune(now + 10000000001n);
    ({ shouldBlock } = rate.bytesReceived(now, addr, 1));
    assert(!shouldBlock);
  });

  it('burst', async () => {
    const addr = 'yada';

    let now = 100n;
    let shouldBlock = null;

    const rate = new RateLimit(1, 5);

    for (let i = 0; i < 5; ++i) {
      ({ shouldBlock } = rate.bytesReceived(now, addr, 1));
      assert(!shouldBlock);
    }

    ({ shouldBlock } = rate.bytesReceived(now, addr, 1));
    assert(shouldBlock);

    now += 2n;

    ({ shouldBlock } = rate.bytesReceived(now, addr, 1));
    assert(!shouldBlock);
  });
  */
});
