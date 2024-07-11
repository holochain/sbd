import { DurableObject } from 'cloudflare:workers';
import { Prom } from './prom.ts';
import { RateLimit, RateLimitResult } from './rate-limit.ts';
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

/**
 * How long to wait ahead of "now" to batch up message sends.
 * Note, we're setting this to zero which will try to send queued messages
 * as fast as possible. This doesn't mean messages won't be queued/batched,
 * since there will be a delay between requesting an alarm and when it
 * is actually invoked + however long it takes to actually run.
 */
const BATCH_DUR_MS = 0;

/**
 * How many nanoseconds of rate limiting quota should be burned by a single
 * byte sent through the system. Higher numbers mean slower rate limiting.
 */
const LIMIT_NANOS_PER_BYTE = 8000;

/**
 * Milliseconds connections are allowed to remain idle before being closed.
 */
const LIMIT_IDLE_MILLIS = 10000;

/**
 * Max message size.
 */
const MAX_MESSAGE_BYTES = 20000;

/**
 * Cloudflare worker environment objects.
 */
export interface Env {
  SBD_COORDINATION: KVNamespace;
  SIGNAL: DurableObjectNamespace;
  RATE_LIMIT: DurableObjectNamespace;
}

/**
 * Seconds since epoch timestamp.
 */
function timestamp(): number {
  return (Date.now() / 1000) | 0;
}

/**
 * Pull pubKey string and bytes from the url path.
 */
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

/**
 * This is the http entrypoint.
 * Forward the request to the "SIGNAL" durable object.
 */
export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    try {
      const ip = request.headers.get('cf-connecting-ip') || 'no-ip';

      const method = request.method;
      const url = new URL(request.url);

      // TODO - check headers for content-length / chunked encoding and reject?

      if (method !== 'GET') {
        throw err('expected GET', 400);
      }

      let pathParts = url.pathname.split('/')

      if (pathParts.length === 4 && pathParts[1] === 'metrics') {
        if (env['METRICS_API_' + pathParts[2]] !== pathParts[3]) {
          throw err('bad metrics api key', 400);
        }

        const p = new Prom();

        let res = await env.SBD_COORDINATION.list({ prefix: 'client' });

        let count = 0;

        while (true) {
          for (const item of res.keys) {
            if ('name' in item) {
              count += 1;

              const opened = item.metadata.opened || 0;
              const active = item.metadata.active || 0;
              const ip = item.metadata.ip || 'no-ip';
              const activeBytesReceived = item.metadata.activeBytesReceived || 0;
              p.guage(
                false,
                'client.recv.byte.count',
                'bytes received from client',
                { name: item.name.split(':')[1], opened, active, ip },
                activeBytesReceived
              );
            }
          }

          if (res.list_complete) {
            break;
          }

          res = await env.SBD_COORDINATION.list({ prefix: 'client', cursor: res.cursor });
        }

        p.guage(
          true,
          'client.count',
          'active client count',
          {},
          count
        );

        return new Response(await p.render());
      }

      const { pubKeyStr } = parsePubKey(url.pathname);

      const ipId = env.RATE_LIMIT.idFromName(ip);
      const ipStub = env.RATE_LIMIT.get(ipId) as DurableObjectStub<DoRateLimit>;
      const { shouldBlock } = await ipStub.bytesReceived(
        Date.now(),
        pubKeyStr,
        1,
      );
      if (shouldBlock) {
        throw err(`limit`, 429);
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

/**
 * "RATE_LIMIT" durable object.
 * This is a thin wrapper around the "RateLimit" class.
 */
export class DoRateLimit extends DurableObject {
  ctx: DurableObjectState;
  env: Env;
  rl: RateLimit;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
    this.rl = new RateLimit(LIMIT_NANOS_PER_BYTE, 16 * 16 * 1024);
  }

  async bytesReceived(
    now: number,
    pk: string,
    bytes: number,
  ): Promise<RateLimitResult> {
    return this.rl.bytesReceived(now, pk, bytes);
  }
}

/**
 * "SIGNAL" durable object.
 */
export class DoSignal extends DurableObject {
  ctx: DurableObjectState;
  env: Env;
  queue: { [index: string]: Array<Uint8Array> };
  alarmLock: boolean;
  curLimit: number;
  active: number;
  lastCoord: number;
  activeBytesReceived: number;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
    this.queue = {};
    this.alarmLock = false;
    this.curLimit = 0;
    this.active = timestamp();
    this.lastCoord = timestamp();
    this.activeBytesReceived = 0;
  }

  /**
   * Client websockets are connected to a durable object identified
   * by their own pubKey. When they send forward messages, those must
   * be sent to durable objects identified by the destination pubKey.
   * This is the api for those messages to be forwarded.
   */
  async forward(messageList: Array<Uint8Array>) {
    for (const ws of this.ctx.getWebSockets()) {
      for (const message of messageList) {
        ws.send(message);
      }
    }
  }

  /**
   * This is the http endpoint for the "SIGNAL" durable object.
   * The worker http fetch endpoint above forwards the request here.
   * This function performs some checks, then upgrades the connection
   * to a websocket.
   */
  async fetch(request: Request): Promise<Response> {
    let cleanServer = null;
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
      cleanServer = server;

      const nonce = new Uint8Array(32);
      crypto.getRandomValues(nonce);

      const opened = timestamp();

      server.serializeAttachment({
        pubKey: pubKeyBytes,
        ip,
        nonce,
        valid: false,
        opened,
      });

      // this will also send MsgLbrt
      await this.ipRateLimit(ip, pubKeyStr, 1, server);

      server.send(new MsgLidl(LIMIT_IDLE_MILLIS).encoded());
      server.send(new MsgAreq(nonce).encoded());

      console.log(
        'webSocketOpen',
        JSON.stringify({
          opened,
          active: this.active,
          pubKey: pubKeyStr,
          ip,
          nonce: toB64Url(nonce),
        }),
      );

      return new Response(null, { status: 101, webSocket: client });
    } catch (e: any) {
      console.error('error', e.toString());
      if (cleanServer) {
        cleanServer.close(4000 + (e.status || 500), e.toString());
      }
      return new Response(JSON.stringify({ err: e.toString() }), {
        status: e.status || 500,
      });
    }
  }

  /**
   * Helper function for performing the rate-limit check and
   * closing the websocket if we violate the limit.
   */
  async ipRateLimit(ip: string, pk: string, bytes: number, ws: WebSocket) {
    try {
      const ipId = this.env.RATE_LIMIT.idFromName(ip);
      const ipStub = this.env.RATE_LIMIT.get(
        ipId,
      ) as DurableObjectStub<DoRateLimit>;
      const { limitNanosPerByte, shouldBlock } = await ipStub.bytesReceived(
        Date.now(),
        pk,
        bytes,
      );
      if (shouldBlock) {
        throw err(`limit`, 429);
      }
      if (this.curLimit !== limitNanosPerByte) {
        this.curLimit = limitNanosPerByte;
        ws.send(new MsgLbrt(limitNanosPerByte).encoded());
      }
    } catch (e) {
      throw err(`limit ${e}`, 429);
    }
  }

  /**
   * Handle incoming websocket messages.
   * First handshake the connection, then start handling forwarding messages.
   */
  async webSocketMessage(ws: WebSocket, message: ArrayBuffer | string) {
    await this.ctx.blockConcurrencyWhile(async () => {
      try {
        const { pubKey, ip, nonce, valid, opened } = ws.deserializeAttachment();
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

        this.activeBytesReceived += msgRaw.byteLength;
        await this.ipRateLimit(ip, pubKey, msgRaw.byteLength, ws);

        if (msgRaw.byteLength > MAX_MESSAGE_BYTES) {
          throw err('max message length exceeded', 400);
        }

        const pubKeyStr = toB64Url(pubKey);

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
              opened
            });

            console.log(
              'webSocketAuthenticated',
              JSON.stringify({ opened, active: this.active, pubKey: pubKeyStr }),
            );

            const metadata = { opened, active: this.active, activeBytesReceived: this.activeBytesReceived, ip };
            await this.env.SBD_COORDINATION.put(
              `client:${pubKeyStr}`,
              JSON.stringify(metadata),
              { expirationTtl: 60, metadata }
            );

            this.lastCoord = timestamp();
          } else {
            if (msg instanceof MsgForward) {
              throw err(`invalid forward before handshake`);
            }
            // otherwise just ignore the message
          }
        } else {
          if (timestamp() - this.lastCoord >= 30) {
            const metadata = { opened, active: this.active, activeBytesReceived: this.activeBytesReceived, ip };
            await this.env.SBD_COORDINATION.put(
              `client:${pubKeyStr}`,
              JSON.stringify(metadata),
              { expirationTtl: 60, metadata }
            );
          }

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
      } catch (e: any) {
        console.error('error', e.toString());
        ws.close(4000 + (e.status || 500), e.toString());
      }
    });
  }

  /**
   * The `webSocketMessage` handler above enqueues messages for delivery,
   * then sets up an alarm to handle actually forwarding them. This ensures
   * the messages are delivered in order without deadlocking two clients
   * that happened to try to forward messages to each other at the same moment.
   */
  async alarm() {
    const { shouldReturn, queue } = await this.ctx.blockConcurrencyWhile(
      async () => {
        if (this.alarmLock || Object.keys(this.queue).length === 0) {
          return { shouldReturn: true, queue: {} };
        }
        this.alarmLock = true;
        const queue = this.queue;
        this.queue = {};
        return { shouldReturn: false, queue };
      },
    );

    if (shouldReturn) {
      return;
    }

    // We cannot do the actual forwarding within a blockConcurrency because
    // then if two peers try to send each other data at the same time it
    // will deadlock. Hence all the complexity with the alarms and alarmLock.

    for (const idName in queue) {
      try {
        const id = this.env.SIGNAL.idFromName(idName);
        const stub = this.env.SIGNAL.get(id) as DurableObjectStub<DoSignal>;

        await stub.forward(queue[idName]);
      } catch (_e: any) {
        // It is okay to get errors forwarding to peers, they may have
        // disconnected. We still want to forward to other peers who
        // may still be there.
      }
    }

    await this.ctx.blockConcurrencyWhile(async () => {
      this.alarmLock = false;

      if (Object.keys(this.queue).length !== 0) {
        const alarm = await this.ctx.storage.getAlarm();
        if (!alarm) {
          this.ctx.storage.setAlarm(Date.now() + BATCH_DUR_MS);
        }
      }
    });
  }

  /**
   * The websocket was closed.
   */
  async webSocketClose(
    ws: WebSocket,
    code: number,
    reason: string,
    wasClean: boolean,
  ) {
    const { pubKey, ip, nonce, valid, opened } = ws.deserializeAttachment();
    console.log(
      'webSocketClose',
      JSON.stringify({
        opened,
        active: this.active,
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
