use super::*;

use std::collections::VecDeque;

pub struct SendBuf {
    pub ws: raw_client::WsRawSend,
    pub buf: VecDeque<(PubKey, Vec<u8>)>,
    pub out_buffer_size: usize,
    pub origin: tokio::time::Instant,
    pub limit_rate: u64,
    pub idle_keepalive_nanos: u64,
    pub next_send_at: u64,
    pub last_send: u64,
}

impl SendBuf {
    /// construct a new send buf
    pub fn new(
        ws: raw_client::WsRawSend,
        out_buffer_size: usize,
        limit_rate: u64,
        idle_keepalive: std::time::Duration,
        pre_sent_bytes: usize,
    ) -> Self {
        let mut this = Self {
            ws,
            buf: VecDeque::default(),
            out_buffer_size,
            origin: tokio::time::Instant::now(),
            limit_rate,
            idle_keepalive_nanos: idle_keepalive.as_nanos() as u64,
            next_send_at: 0,
            last_send: 0,
        };

        let now = this.origin.elapsed().as_nanos() as u64;

        this.next_send_at = std::cmp::max(now, this.next_send_at)
            + (pre_sent_bytes as u64 * this.limit_rate);

        this
    }

    /// We received a new rate limit from the server, update our records.
    pub fn new_rate_limit(&mut self, limit: u64) {
        if limit < self.limit_rate {
            // rate limit updates are sent on a best effort,
            // and there are network timing conditions to worry about.
            // assume we accidentally sent a message while the new limit
            // was in effect, and accout for that in a brute-force manner.

            let now = self.origin.elapsed().as_nanos() as u64;

            self.next_send_at = std::cmp::max(now, self.next_send_at)
                + (MAX_MSG_SIZE as u64 * self.limit_rate);
        }
        self.limit_rate = limit;
    }

    /// If we need to wait before taking the next step, this
    /// returns how long.
    pub fn next_step_dur(&self) -> Option<std::time::Duration> {
        let now = self.origin.elapsed().as_nanos() as u64;

        if now - self.last_send >= self.idle_keepalive_nanos {
            // we need a keepalive now, don't wait
            return None;
        }

        if now < self.next_send_at {
            let need_keepalive_at =
                self.idle_keepalive_nanos - (now - self.last_send);
            let nanos =
                std::cmp::min(need_keepalive_at, self.next_send_at - now);
            Some(std::time::Duration::from_nanos(nanos))
        } else {
            None
        }
    }

    /// Call `next_step_dur()` first. If it returns None, or you
    /// await the Duration returned, call this function to send
    /// out the next queued block on the low-level websocket.
    /// Returns true if it did something, false if it did not.
    pub async fn write_next_queued(&mut self) -> Result<bool> {
        let now = self.origin.elapsed().as_nanos() as u64;

        // first check if we need to keepalive
        if now - self.last_send >= self.idle_keepalive_nanos {
            let mut data = Vec::with_capacity(32);
            data.extend_from_slice(CMD_FLAG);
            data.extend_from_slice(b"keep");
            self.raw_send(now, data).await?;
            return Ok(true);
        }

        if self.next_step_dur().is_some() {
            return Ok(false);
        }

        if let Some((_, data)) = self.buf.pop_front() {
            self.raw_send(now, data).await?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// If our buffer is over our buffer size, do the work to get it under.
    /// Then queue up data to be sent out.
    /// Note, you'll need to explicitly call `write_next_queued()` or
    /// make additional sends in order to get this queued data actually sent.
    pub async fn send(&mut self, pk: &PubKey, mut data: &[u8]) -> Result<()> {
        while !self.space_free() {
            if let Some(dur) = self.next_step_dur() {
                tokio::time::sleep(dur).await;
            }
            self.write_next_queued().await?;
        }

        self.check_set_prebuffer();

        // first try to put into existing blocks
        for (qpk, qdata) in self.buf.iter_mut() {
            if qpk == pk && qdata.len() < MAX_MSG_SIZE {
                let amt = std::cmp::min(data.len(), MAX_MSG_SIZE - qdata.len());
                qdata.extend_from_slice(&data[..amt]);
                data = &data[amt..];
                if data.is_empty() {
                    return Ok(());
                }
            }
        }

        // next, fill out new entries
        while !data.is_empty() {
            let mut init = Vec::with_capacity(MAX_MSG_SIZE);
            init.extend_from_slice(&pk.0[..]);

            let amt = std::cmp::min(data.len(), MAX_MSG_SIZE - init.len());
            init.extend_from_slice(&data[..amt]);
            data = &data[amt..];
            self.buf.push_back((*pk, init));
        }

        Ok(())
    }

    // -- private -- //

    async fn raw_send(&mut self, now: u64, data: Vec<u8>) -> Result<()> {
        self.next_send_at = std::cmp::max(now, self.next_send_at)
            + (data.len() as u64 * self.limit_rate);

        self.ws.send(data).await?;
        self.last_send = now;

        Ok(())
    }

    fn len(&self) -> usize {
        self.buf.iter().map(|(_, d)| d.len()).sum()
    }

    /// If we have an empty out buffer, set some rate-limit as a hack
    /// for waiting a little bit to see if more sends come in and can
    /// be aggregated
    fn check_set_prebuffer(&mut self) {
        if self.buf.is_empty() {
            let hack = self.origin.elapsed().as_nanos() as u64 + 10_000_000; // 10 millis in nanos
            self.next_send_at = std::cmp::max(hack, self.next_send_at)
        }
    }

    /// Returns `true` if our total buffer size < out_buffer_size
    fn space_free(&self) -> bool {
        self.len() < self.out_buffer_size
    }
}
