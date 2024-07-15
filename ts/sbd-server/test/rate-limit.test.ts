import { env, runInDurableObject } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import { DoRateLimit } from '../src';

it('rate-limit sanity', async () => {
  const test = '1';
  const ip = `ip${test}`;
  const pk = `pk${test}`;

  const id = env.RATE_LIMIT.idFromName(ip);
  const stub = env.RATE_LIMIT.get(id);
  await runInDurableObject(stub, async (inst: DoRateLimit) => {
    const res = await inst.bytesReceived(Date.now(), ip, pk, 1);
    expect(res.shouldBlock).equals(false);
  });
});

it('rate-limit causes block', async () => {
  const test = '2';
  const ip = `ip${test}`;
  const pk = `pk${test}`;

  const id = env.RATE_LIMIT.idFromName(ip);
  const stub = env.RATE_LIMIT.get(id);
  await runInDurableObject(stub, async (inst: DoRateLimit) => {
    const res = await inst.bytesReceived(
      Date.now(),
      ip,
      pk,
      Number.MAX_SAFE_INTEGER,
    );
    expect(res.shouldBlock).equals(true);
  });

  const kvBlock = await env.SBD_COORDINATION.get(`block:${ip}`, {
    type: 'json',
  });
  expect(kvBlock).equals(true);
});

it('rate-limit load checks kv block', async () => {
  const test = '3';
  const ip = `ip${test}`;
  const pk = `pk${test}`;

  await env.SBD_COORDINATION.put(`block:${ip}`, 'true', {
    expirationTtl: 60 * 10,
  });

  const id = env.RATE_LIMIT.idFromName(ip);
  const stub = env.RATE_LIMIT.get(id);
  await runInDurableObject(stub, async (inst: DoRateLimit) => {
    const res = await inst.bytesReceived(Date.now(), ip, pk, 1);
    expect(res.shouldBlock).equals(true);
  });
});

it('rate-limit slower for multi-con ips', async () => {
  const test = '4';
  const ip = `ip${test}`;

  const id = env.RATE_LIMIT.idFromName(ip);
  const stub = env.RATE_LIMIT.get(id);

  const rate1 = await runInDurableObject(stub, async (inst: DoRateLimit) => {
    const res = await inst.bytesReceived(Date.now(), ip, 'pkA', 1);
    return res.limitNanosPerByte;
  });

  const rate2 = await runInDurableObject(stub, async (inst: DoRateLimit) => {
    const res = await inst.bytesReceived(Date.now(), ip, 'pkB', 1);
    return res.limitNanosPerByte;
  });

  expect(rate2).equals(rate1 * 2);

  const rate3 = await runInDurableObject(stub, async (inst: DoRateLimit) => {
    const res = await inst.bytesReceived(Date.now(), ip, 'pkC', 1);
    return res.limitNanosPerByte;
  });

  expect(rate3).equals(rate1 * 3);

  const rate1Again = await runInDurableObject(
    stub,
    async (inst: DoRateLimit) => {
      const res = await inst.bytesReceived(Date.now(), ip, 'pkA', 1);
      return res.limitNanosPerByte;
    },
  );

  expect(rate1Again).equals(rate3);
});
