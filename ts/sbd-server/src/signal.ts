import { DurableObject } from 'cloudflare:workers';

import * as common from './common.ts';

import { DoRateLimit } from './rate-limit.ts';
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
  status: number;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
    this.queue = {};
    this.alarmLock = false;
    this.curLimit = 0;
    this.active = common.timestamp();
    this.lastCoord = common.timestamp();
    this.activeBytesReceived = 0;
    this.status = 200;
  }

  /**
   * Client websockets are connected to a durable object identified
   * by their own pubKey. When they send forward messages, those must
   * be sent to durable objects identified by the destination pubKey.
   * This is the api for those messages to be forwarded.
   */
  async forward(messageList: Array<Uint8Array>) {
    if (this.status !== 200) {
      return;
    }

    // MAYBE: buffer messages until handshake complete?
    //        might not be needed since clients shouldn't publish the address
    //        until handshake is complete

    // This loop not technically needed, since our fetch ensures there
    // is only ever one websocket connected.
    for (const ws of this.ctx.getWebSockets()) {
      for (const message of messageList) {
        try {
          ws.send(message);
        } catch (e: any) {
          console.error('forward error', e);
          this.status = 500;
          return;
        }
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
    if (this.status !== 200) {
      return new Response(JSON.stringify({ err: 'dead' }), {
        status: this.status,
      });
    }

    let cleanServer = null;
    try {
      const ip = request.headers.get('cf-connecting-ip') || 'no-ip';
      const url = new URL(request.url);

      const { pubKeyStr, pubKeyBytes } = common.parsePubKey(url.pathname);

      if (this.ctx.getWebSockets().length > 0) {
        throw common.err('websocket already connected', 400);
      }
      if (request.headers.get('Upgrade') !== 'websocket') {
        throw common.err('expected websocket', 426);
      }

      const [client, server] = Object.values(new WebSocketPair());

      this.ctx.acceptWebSocket(server);
      cleanServer = server;

      const nonce = new Uint8Array(32);
      crypto.getRandomValues(nonce);

      const opened = common.timestamp();

      server.serializeAttachment({
        pubKey: pubKeyBytes,
        ip,
        nonce,
        valid: false,
        opened,
      });

      // this will also send MsgLbrt
      await this.ipRateLimit(ip, pubKeyStr, 1, server);

      server.send(new MsgLidl(common.LIMIT_IDLE_MILLIS).encoded());
      server.send(new MsgAreq(nonce).encoded());

      console.log(
        'webSocketOpen',
        JSON.stringify({
          opened,
          active: this.active,
          pubKey: pubKeyStr,
          ip,
          nonce: common.toB64Url(nonce),
        }),
      );

      return new Response(null, { status: 101, webSocket: client });
    } catch (e: any) {
      // Note: one might be tempted to set this.status here, but then bad
      //       actors could maliciously drop other peer connections just
      //       by trying (and failing) to connect to them.

      console.error('error', e.toString());
      if (cleanServer) {
        // Note: HERE it's okay to set this.status, since we know we're
        //       the original connecting websocket.
        this.status = e.status || 500;
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
    // disabling rate limiting temporarily as an experiment
    const HACK_NANOS_PER_BYTE = 1;
    if (this.curLimit !== HACK_NANOS_PER_BYTE) {
      this.curLimit = HACK_NANOS_PER_BYTE;
      ws.send(new MsgLbrt(HACK_NANOS_PER_BYTE).encoded());
    }
    /*
    try {
      const ipId = this.env.RATE_LIMIT.idFromName(ip);
      const ipStub = this.env.RATE_LIMIT.get(
        ipId,
      ) as DurableObjectStub<DoRateLimit>;
      const { limitNanosPerByte, shouldBlock } = await ipStub.bytesReceived(
        Date.now(),
        ip,
        pk,
        bytes,
      );
      if (shouldBlock) {
        throw common.err(`limit`, 429);
      }
      if (this.curLimit !== limitNanosPerByte) {
        this.curLimit = limitNanosPerByte;
        ws.send(new MsgLbrt(limitNanosPerByte).encoded());
      }
    } catch (e) {
      throw common.err(`limit ${e}`, 429);
    }
    */
  }

  /**
   * Handle incoming websocket messages.
   * First handshake the connection, then start handling forwarding messages.
   */
  async webSocketMessage(ws: WebSocket, message: ArrayBuffer | string) {
    if (this.status !== 200) {
      ws.close(4000 + this.status, 'dead');
      return;
    }

    await this.ctx.blockConcurrencyWhile(async () => {
      try {
        const { pubKey, ip, nonce, valid, opened } = ws.deserializeAttachment();
        if (!pubKey) {
          throw common.err('no associated pubKey');
        }
        if (!ip) {
          throw common.err('no associated ip');
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

        if (msgRaw.byteLength > common.MAX_MESSAGE_BYTES) {
          throw common.err('max message length exceeded', 400);
        }

        const pubKeyStr = common.toB64Url(pubKey);

        const msg = Msg.parse(msgRaw);

        if (!valid) {
          if (!nonce) {
            throw common.err('no associated nonce');
          }

          if (msg instanceof MsgAres) {
            if (!common.ed.verify(msg.signature(), nonce, pubKey)) {
              throw common.err('invalid handshake signature', 400);
            }

            ws.send(new MsgSrdy().encoded());

            ws.serializeAttachment({
              pubKey,
              ip,
              nonce: true, // don't need to keep the actual nonce anymore
              valid: true,
              opened,
            });

            console.log(
              'webSocketAuthenticated',
              JSON.stringify({
                opened,
                active: this.active,
                pubKey: pubKeyStr,
              }),
            );

            this.lastCoord = common.timestamp();
            const metadata = {
              op: opened,
              ac: this.active,
              br: this.activeBytesReceived,
              ip,
            };
            await this.env.SBD_COORDINATION.put(
              `client:${pubKeyStr}`,
              JSON.stringify(metadata),
              { expirationTtl: 60, metadata },
            );
          } else {
            if (msg instanceof MsgForward) {
              throw common.err(`invalid forward before handshake`);
            }
            // otherwise just ignore the message
          }
        } else {
          if (common.timestamp() - this.lastCoord >= 30) {
            this.lastCoord = common.timestamp();
            const metadata = {
              op: opened,
              ac: this.active,
              br: this.activeBytesReceived,
              ip,
            };
            await this.env.SBD_COORDINATION.put(
              `client:${pubKeyStr}`,
              JSON.stringify(metadata),
              { expirationTtl: 60, metadata },
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

            const id = common.toB64Url(dest);
            if (!this.queue[id]) {
              this.queue[id] = [];
            }
            this.queue[id].push(msg.encoded());

            if (!this.alarmLock) {
              const alarm = await this.ctx.storage.getAlarm();
              if (!alarm) {
                this.ctx.storage.setAlarm(Date.now() + common.BATCH_DUR_MS);
              }
            }
          } else {
            throw common.err(
              `invalid post-handshake message type: ${msg.type()}`,
            );
          }
        }
      } catch (e: any) {
        console.error('error', e.toString());
        this.status = e.status || 500;
        ws.close(4000 + this.status, e.toString());
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
    if (this.status !== 200) {
      return;
    }

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
          this.ctx.storage.setAlarm(Date.now() + common.BATCH_DUR_MS);
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
        pubKey: common.toB64Url(pubKey),
        ip,
        nonce: nonce instanceof Uint8Array ? common.toB64Url(nonce) : nonce,
        valid,
        code,
        reason,
        wasClean,
      }),
    );
  }
}
