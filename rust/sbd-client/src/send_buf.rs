use super::*;

use std::collections::VecDeque;

pub struct SendBuf {
    pub ws: raw_client::WsRawSend,
    pub buf: VecDeque<(PubKey, Vec<u8>)>,
    pub out_buffer_size: usize,
    pub origin: tokio::time::Instant,
    pub limit_rate: u64,
    pub next_send_at: u64,
}

impl SendBuf {
    /// If we need to wait before taking the next step, this
    /// returns how long.
    pub fn next_step_dur(&self) -> Option<std::time::Duration> {
        let now = self.origin.elapsed().as_nanos() as u64;
        if now < self.next_send_at {
            Some(std::time::Duration::from_nanos(self.next_send_at - now))
        } else {
            None
        }
    }

    /// Call `next_step_dur()` first. If it returns None, or you
    /// await the Duration returned, call this function to send
    /// out the next queued block on the low-level websocket.
    /// Returns true if it did something, false if it did not.
    pub async fn write_next_queued(&mut self) -> Result<bool> {
        // check the dur again, just to avoid race conditions
        // sending too much data at once
        if self.next_step_dur().is_some() {
            return Ok(false);
        }

        if let Some((_, data)) = self.buf.pop_front() {
            let now = self.origin.elapsed().as_nanos() as u64;
            let next_send_at =
                self.next_send_at + (data.len() as u64 * self.limit_rate);
            self.next_send_at = std::cmp::max(now, next_send_at);
            self.ws.send(data).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// If our buffer is over our buffer size, do the work to get it under.
    /// Then queue up data to be sent out.
    /// Note, you'll need to explicitly call `process_next_step()` or
    /// make additional sends in order to get this queued data actually sent.
    pub async fn send(&mut self, pk: &PubKey, mut data: &[u8]) -> Result<()> {
        while !self.space_free() {
            if let Some(dur) = self.next_step_dur() {
                tokio::time::sleep(dur).await;
            }
            self.write_next_queued().await?;
        }

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
            self.buf.push_back((pk.clone(), init));
        }

        Ok(())
    }

    // -- private -- //

    fn len(&self) -> usize {
        self.buf.iter().map(|(_, d)| d.len()).sum()
    }

    /// Returns `true` if our total buffer size < out_buffer_size
    fn space_free(&self) -> bool {
        self.len() < self.out_buffer_size
    }
}
