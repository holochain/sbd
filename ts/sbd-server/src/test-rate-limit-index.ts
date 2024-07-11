// THIS IS A FAKE index.ts to be used for unit testing the
// DoRateLimit durable object.

import * as common from './common.ts';

import { DoRateLimit } from './rate-limit.ts';
export { DoRateLimit };

import { DoSignal } from './signal.ts';
export { DoSignal };

export default {
  async fetch(
    request: Request,
    env: common.Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    return new Response('bob');
  },
};
