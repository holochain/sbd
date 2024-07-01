import { RateLimit } from './rate-limit.ts';
import { err } from './err.ts';
import { ed } from './ed.ts';
import { toB64Url, fromB64Url } from './b64.ts';
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

export interface Env {
  SIGNAL: DurableObjectNamespace;
  RATE_LIMIT: DurableObjectNamespace;
}

async function ipRateLimit(env: Env, ip: string) {
  try {
    const ipId = env.RATE_LIMIT.idFromName(ip);
    const ipStub = env.RATE_LIMIT.get(ipId);
    const res = await ipStub.fetch(new Request(`http://do`));
    if (res.status !== 200) {
      throw err(`limit bad status ${res.status}`, 429);
    }
    const { limit } = (await res.json()) as { limit: number };
    if (limit > 0) {
      throw err(`limit ${limit}`, 429);
    }
  } catch (e) {
    throw err(`limit ${e}`, 429);
  }
}

function parsePubKey(path: string): {
  pubKeyStr: string;
  pubKeyBytes: Uint8Array;
} {
  const parts: Array<string> = path.split('/');

  if (parts.length !== 2) {
    throw err('expected single pubKey item on path', 400);
  }

  const pubKeyStr = parts[1];

  const pubKeyBytes = fromB64Url(parts[1]);

  if (pubKeyBytes.length !== 32) {
    throw err('invalid pubKey length', 400);
  }

  return { pubKeyStr, pubKeyBytes };
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    try {
      const ip = request.headers.get('cf-connecting-ip') || 'no-ip';

      await ipRateLimit(env, ip);

      const method = request.method;
      const url = new URL(request.url);

      // TODO - check headers for content-length / chunked encoding and reject?

      if (method !== 'GET') {
        throw err('expected GET', 400);
      }

      const { pubKeyStr } = parsePubKey(url.pathname);

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

export class DoRateLimit implements DurableObject {
  state: DurableObjectState;
  env: Env;
  rl: RateLimit;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
    this.rl = new RateLimit(5000);
  }

  async fetch(request: Request): Promise<Response> {
    return Response.json({ limit: this.rl.trackRequest(Date.now(), 1) });
  }
}

export class DoSignal implements DurableObject {
  state: DurableObjectState;
  env: Env;
  rl: RateLimit;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
    this.rl = new RateLimit(5000);
  }

  async fetch(request: Request): Promise<Response> {
    return await this.state.blockConcurrencyWhile(async () => {
      try {
        const ip = request.headers.get('cf-connecting-ip') || 'no-ip';
        const url = new URL(request.url);

        if (url.pathname === '/fwd') {
          const message = await request.arrayBuffer();
          for (const ws of this.state.getWebSockets()) {
            ws.send(message);
          }
          return new Response('ok');
        } else {
          const { pubKeyStr, pubKeyBytes } = parsePubKey(url.pathname);

          if (this.state.getWebSockets().length > 0) {
            throw err('websocket already connected', 400);
          }
          if (request.headers.get('Upgrade') !== 'websocket') {
            throw err('expected websocket', 426);
          }

          const [client, server] = Object.values(new WebSocketPair());

          this.state.acceptWebSocket(server);

          const nonce = new Uint8Array(32);
          crypto.getRandomValues(nonce);

          server.serializeAttachment({
            pubKey: pubKeyBytes,
            ip,
            nonce,
            valid: false,
          });

          server.send(new MsgLbrt(8000).encoded());
          server.send(new MsgLidl(10000).encoded());
          server.send(new MsgAreq(nonce).encoded());

          console.log(
            'webSocketOpen',
            JSON.stringify({
              pubKey: pubKeyStr,
              ip,
              nonce: toB64Url(nonce),
            }),
          );

          return new Response(null, { status: 101, webSocket: client });
        }
      } catch (e: any) {
        console.error('error', e.toString());
        return new Response(JSON.stringify({ err: e.toString() }), {
          status: e.status || 500,
        });
      }
    });
  }

  // handle incoming websocket messages
  async webSocketMessage(ws: WebSocket, message: ArrayBuffer | string) {
    await this.state.blockConcurrencyWhile(async () => {
      try {
        const { pubKey, ip, nonce, valid } = ws.deserializeAttachment();
        if (!pubKey) {
          throw err('no associated pubKey');
        }
        if (!ip) {
          throw err('no associated ip');
        }

        await ipRateLimit(this.env, ip);

        if (this.rl.trackRequest(Date.now(), 20) > 0) {
          throw err('rate limit', 429);
        }

        // convert strings into binary
        let msgRaw: Uint8Array;
        if (message instanceof ArrayBuffer) {
          msgRaw = new Uint8Array(message);
        } else {
          const enc = new TextEncoder();
          msgRaw = enc.encode(message);
        }

        const msg = Msg.parse(msgRaw);

        if (!valid) {
          if (!nonce) {
            throw err('no associated nonce');
          }

          if (msg instanceof MsgAres) {
            if (!ed.verify(msg.signature(), nonce, pubKey)) {
              throw err('invalid handshake signature', 400);
            }
            console.log('webSocketSignatureVerified');

            ws.send(new MsgSrdy().encoded());

            ws.serializeAttachment({
              pubKey,
              ip,
              nonce: true, // don't need to keep the actual nonce anymore
              valid: true,
            });
          } else {
            throw err(`invalid handshake message type ${msg.type()}`);
          }
        } else {
          if (msg instanceof MsgNone) {
            // no-op
          } else if (msg instanceof MsgKeep) {
            // keep alive
          } else if (msg instanceof MsgForward) {
            // extract the destination pubKey (slice does a copy)
            const dest = msg.pubKey().slice(0);

            // overwrite the destination pubKey with the source (our) pubKey
            // the pubKey() function returns a reference, so editing it
            // alters the message that will be sent
            msg.pubKey().set(pubKey, 0);

            const req = new Request('http://do/fwd', {
              method: 'POST',
              body: msg.encoded(),
            });

            const id = this.env.SIGNAL.idFromName(toB64Url(dest));
            const stub = this.env.SIGNAL.get(id);

            // intentionally ignore errors here
            await stub.fetch(req);
          } else {
            throw err(`invalid post-handshake message type: ${msg.type()}`);
          }
        }
      } catch (e: any) {
        console.error('error', e.toString());
        ws.close(4000 + (e.status || 500), e.toString());
      }
    });
  }

  async webSocketClose(
    ws: WebSocket,
    code: number,
    reason: string,
    wasClean: boolean,
  ) {
    const { pubKey, ip, nonce, valid } = ws.deserializeAttachment();
    console.log(
      'webSocketClose',
      JSON.stringify({
        pubKey: toB64Url(pubKey),
        ip,
        nonce: nonce instanceof Uint8Array ? toB64Url(nonce) : nonce,
        valid,
        code,
        reason,
        wasClean,
      }),
    );
  }
}
