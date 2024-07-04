import { DurableObject } from 'cloudflare:workers';
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

const BATCH_DUR_MS = 20;

export interface Env {
  SIGNAL: DurableObjectNamespace;
  RATE_LIMIT: DurableObjectNamespace;
}

async function ipRateLimit(env: Env, ip: string) {
  try {
    const ipId = env.RATE_LIMIT.idFromName(ip);
    const ipStub = env.RATE_LIMIT.get(ipId) as DurableObjectStub<DoRateLimit>;
    const limit = await ipStub.trackRequest(Date.now(), 1);
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

export class DoRateLimit extends DurableObject {
  ctx: DurableObjectState;
  env: Env;
  rl: RateLimit;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
    this.rl = new RateLimit(5000);
  }

  async trackRequest(now: number, reqWeightMs: number): Promise<number> {
    return this.rl.trackRequest(now, reqWeightMs);
  }
}

export class DoSignal extends DurableObject {
  ctx: DurableObjectState;
  env: Env;
  queue: { [index: string]: Array<Uint8Array> };
  alarmLock: boolean;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
    this.queue = {};
    this.alarmLock = false;
  }

  async forward(messageList: Array<Uint8Array>) {
    for (const ws of this.ctx.getWebSockets()) {
      for (const message of messageList) {
        ws.send(message);
      }
    }
  }

  async fetch(request: Request): Promise<Response> {
    try {
      const ip = request.headers.get('cf-connecting-ip') || 'no-ip';
      const url = new URL(request.url);

      const { pubKeyStr, pubKeyBytes } = parsePubKey(url.pathname);

      if (this.ctx.getWebSockets().length > 0) {
        throw err('websocket already connected', 400);
      }
      if (request.headers.get('Upgrade') !== 'websocket') {
        throw err('expected websocket', 426);
      }

      const [client, server] = Object.values(new WebSocketPair());

      this.ctx.acceptWebSocket(server);

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
    } catch (e: any) {
      console.error('error', e.toString());
      return new Response(JSON.stringify({ err: e.toString() }), {
        status: e.status || 500,
      });
    }
  }

  // handle incoming websocket messages
  async webSocketMessage(ws: WebSocket, message: ArrayBuffer | string) {
    const ip = await this.ctx.blockConcurrencyWhile(async () => {
      try {
        const { pubKey, ip, nonce, valid } = ws.deserializeAttachment();
        if (!pubKey) {
          throw err('no associated pubKey');
        }
        if (!ip) {
          throw err('no associated ip');
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

            ws.send(new MsgSrdy().encoded());

            ws.serializeAttachment({
              pubKey,
              ip,
              nonce: true, // don't need to keep the actual nonce anymore
              valid: true,
            });

            console.log('webSocketAuthenticated');
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

            const id = toB64Url(dest);
            if (!this.queue[id]) {
              this.queue[id] = [];
            }
            this.queue[id].push(msg.encoded());

            if (!this.alarmLock) {
              const alarm = await this.ctx.storage.getAlarm();
              if (!alarm) {
                this.ctx.storage.setAlarm(Date.now() + BATCH_DUR_MS);
              }
            }
          } else {
            throw err(`invalid post-handshake message type: ${msg.type()}`);
          }
        }

        return ip;
      } catch (e: any) {
        console.error('error', e.toString());
        ws.close(4000 + (e.status || 500), e.toString());
      }
    });

    try {
      // NOTE: It's a little odd to run the rate-limiting *after* forwarding,
      //       but this lets our concurrency block be faster without having
      //       to await the rate limit check.
      //
      //       It's not the end of the world if a couple extra messages get
      //       through before the websocket is closed.
      await ipRateLimit(this.env, ip);
    } catch (e: any) {
      console.error('error', e.toString());
      ws.close(4000 + (e.status || 500), e.toString());
    }
  }

  async alarm() {
    const { shouldReturn, queue } = await this.ctx.blockConcurrencyWhile(
      async () => {
        if (this.alarmLock) {
          return { shouldReturn: true, queue: {} };
        }
        this.alarmLock = true;
        const queue = this.queue;
        this.queue = {};
        const shouldReturn = Object.keys(queue).length === 0;
        return { shouldReturn, queue };
      },
    );

    if (shouldReturn) {
      return;
    }

    for (const idName in queue) {
      const id = this.env.SIGNAL.idFromName(idName);
      const stub = this.env.SIGNAL.get(id) as DurableObjectStub<DoSignal>;

      try {
        await stub.forward(queue[idName]);
      } catch (e: any) {
        /* pass */
      }
    }

    await this.ctx.blockConcurrencyWhile(async () => {
      this.alarmLock = false;

      if (Object.keys(this.queue).length !== 0) {
        const alarm = await this.ctx.storage.getAlarm();
        if (!alarm) {
          // batch by 100 millis
          this.ctx.storage.setAlarm(Date.now() + BATCH_DUR_MS);
        }
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
