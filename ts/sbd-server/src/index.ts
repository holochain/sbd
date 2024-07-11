import { DurableObject } from 'cloudflare:workers';

import * as common from './common.ts';

import { Prom } from './prom.ts';

import { DoRateLimit } from './rate-limit.ts';
export { DoRateLimit };

import { DoSignal } from './signal.ts';
export { DoSignal };

/**
 * This is the http entrypoint.
 * Forward the request to the "SIGNAL" durable object.
 */
export default {
  async fetch(
    request: Request,
    env: common.Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    try {
      const ip = request.headers.get('cf-connecting-ip') || 'no-ip';

      const method = request.method;
      const url = new URL(request.url);

      // TODO - check headers for content-length / chunked encoding and reject?

      if (method !== 'GET') {
        throw common.err('expected GET', 400);
      }

      let pathParts = url.pathname.split('/');

      if (pathParts.length === 4 && pathParts[1] === 'metrics') {
        if (env['METRICS_API_' + pathParts[2]] !== pathParts[3]) {
          throw common.err('bad metrics api key', 400);
        }

        const p = new Prom();

        let res = await env.SBD_COORDINATION.list({ prefix: 'client' });

        let count = 0;

        while (true) {
          for (const item of res.keys) {
            if (
              'name' in item &&
              item.metadata &&
              typeof item.metadata === 'object'
            ) {
              count += 1;

              let opened = 0;
              let active = 0;
              let activeBytesReceived = 0;

              if (
                'op' in item.metadata &&
                typeof item.metadata.op === 'number'
              ) {
                opened = item.metadata.op;
              }
              if (
                'ac' in item.metadata &&
                typeof item.metadata.ac === 'number'
              ) {
                active = item.metadata.ac;
              }
              if (
                'br' in item.metadata &&
                typeof item.metadata.br === 'number'
              ) {
                activeBytesReceived = item.metadata.br;
              }

              const now = common.timestamp();

              const openedD = now - opened;
              const activeD = now - active;

              p.guage(
                false,
                'client.recv.byte.count',
                'bytes received from client',
                {
                  name: item.name.split(':')[1],
                  opened,
                  openedD,
                  active,
                  activeD,
                  ip,
                },
                activeBytesReceived,
              );
            }
          }

          if (res.list_complete) {
            break;
          }

          res = await env.SBD_COORDINATION.list({
            prefix: 'client',
            cursor: res.cursor,
          });
        }

        p.guage(true, 'client.count', 'active client count', {}, count);

        return new Response(await p.render());
      }

      const { pubKeyStr } = common.parsePubKey(url.pathname);

      const ipId = env.RATE_LIMIT.idFromName(ip);
      const ipStub = env.RATE_LIMIT.get(ipId) as DurableObjectStub<DoRateLimit>;
      const { shouldBlock } = await ipStub.bytesReceived(
        Date.now(),
        pubKeyStr,
        1,
      );
      if (shouldBlock) {
        throw common.err(`limit`, 429);
      }

      // DO instanced by our pubKey
      const id = env.SIGNAL.idFromName(pubKeyStr);
      const stub = env.SIGNAL.get(id);

      // just forward the full request / response
      return await stub.fetch(request);
    } catch (e: any) {
      console.error('error', e.toString());
      return new Response(JSON.stringify({ err: e.toString() }), {
        status: e.status || 500,
      });
    }
  },
};
