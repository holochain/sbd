//! Attempt to pre-allocate as much as possible, including our tokio tasks.
//! Ideally this would include a frame buffer that we could fill on ws
//! recv and use ase a reference for ws send, but alas, fastwebsockets
//! doesn't seem up to the task. tungstenite will willy-nilly allocate
//! buffers for us, but at least we should only be dealing with one at a
//! time per connection.

use super::*;
use std::sync::{Arc, Mutex, Weak};
use std::collections::HashMap;

static U: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

enum TaskMsg {
    NewWs {
        uniq: u64,
        index: usize,
        ws: Arc<ws::WebSocket<MaybeTlsStream>>,
        ip: Arc<std::net::Ipv6Addr>,
        pk: PubKey,
    },
    Close,
}

struct SlotEntry {
    send: tokio::sync::mpsc::UnboundedSender<TaskMsg>,
}

struct SlabEntry {
    uniq: u64,
    weak_ws: Weak<ws::WebSocket<MaybeTlsStream>>,
}

struct CSlotInner {
    max_count: usize,
    slots: Vec<SlotEntry>,
    slab: slab::Slab<SlabEntry>,
    pk_to_index: HashMap<PubKey, usize>,
    ip_to_index: HashMap<Arc<std::net::Ipv6Addr>, Vec<usize>>,
    task_list: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for CSlotInner {
    fn drop(&mut self) {
        for task in self.task_list.iter() {
            task.abort();
        }
    }
}

struct WeakCSlot(Weak<Mutex<CSlotInner>>);

impl WeakCSlot {
    pub fn upgrade(&self) -> Option<CSlot> {
        self.0.upgrade().map(CSlot)
    }
}

pub struct CSlot(Arc<Mutex<CSlotInner>>);

impl CSlot {
    pub fn new(
        count: usize,
        ip_deny: Arc<ip_deny::IpDeny>,
        ip_rate: Arc<ip_rate::IpRate>,
    ) -> Self {
        Self(Arc::new_cyclic(|this| {
            let mut slots = Vec::with_capacity(count);
            let mut task_list = Vec::with_capacity(count);
            for _ in 0..count {
                let (send, recv) = tokio::sync::mpsc::unbounded_channel();
                slots.push(SlotEntry {
                    send,
                });
                tokio::task::spawn(top_task(
                    ip_deny.clone(),
                    ip_rate.clone(),
                    WeakCSlot(this.clone()),
                    recv,
                ));
            }
            Mutex::new(CSlotInner {
                max_count: count,
                slots,
                slab: slab::Slab::with_capacity(count),
                pk_to_index: HashMap::with_capacity(count),
                ip_to_index: HashMap::with_capacity(count),
                task_list,
            })
        }))
    }

    pub fn remove(&self, uniq: u64, index: usize) {
        let mut lock = self.0.lock().unwrap();

        match lock.slab.get(index) {
            None => return,
            Some(s) => {
                if s.uniq != uniq {
                    return;
                }
            }
        }

        let _ = lock.slots.get(index).unwrap().send.send(TaskMsg::Close);
        lock.slab.remove(index);
        lock.pk_to_index.retain(|_, i| *i != index);
        lock.ip_to_index.retain(|_, v| {
            v.retain(|i| *i != index);
            !v.is_empty()
        });
    }

    pub fn insert(
        &self,
        ip: Arc<std::net::Ipv6Addr>,
        pk: PubKey,
        ws: Arc<ws::WebSocket<MaybeTlsStream>>
    ) -> Result<usize> {
        let mut lock = self.0.lock().unwrap();

        if lock.slab.len() >= lock.max_count {
            return Err(Error::other("too many connections"));
        }

        let weak_ws = Arc::downgrade(&ws);

        let uniq = U.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let index = lock.slab.insert(SlabEntry {
            uniq,
            weak_ws,
        });

        lock.pk_to_index.insert(pk.clone(), index);

        // TODO - should we block more than Vec::with_capacity(count)
        //        connections from the same IP so we avoid allocating
        //        here? Or set this to the max connection count value?

        lock
            .ip_to_index
            .entry(ip.clone())
            .or_insert_with(|| Vec::with_capacity(1024))
            .push(index);

        // TODO - send rate updates to all clients on this ip

        let send = lock.slots.get(index).unwrap().send.clone();
        if send.send(TaskMsg::NewWs { uniq, index, ws, ip, pk }).is_err() {
            return Err(Error::other("closed"));
        }

        Ok(index)
    }

    pub async fn send(
        &self,
        pk: &PubKey,
        payload: Payload<'_>,
    ) -> Result<()> {
        let (uniq, index, ws) = {
            // XXX - DO NOT AWAIT IN THIS BLOCK
            let lock = self.0.lock().unwrap();

            let index = match lock.pk_to_index.get(&pk) {
                None => return Err(Error::other("no such peer")),
                Some(index) => *index,
            };

            let slab = lock.slab.get(index).unwrap();
            let uniq = slab.uniq;
            let ws = match slab.weak_ws.upgrade() {
                None => return Err(Error::other("no such peer")),
                Some(ws) => ws,
            };

            (uniq, index, ws)
        };

        match ws.send(payload).await {
            Err(err) => {
                self.remove(uniq, index);
                Err(err)
            }
            Ok(_) => Ok(()),
        }
    }
}

async fn top_task(
    ip_deny: Arc<ip_deny::IpDeny>,
    ip_rate: Arc<ip_rate::IpRate>,
    weak: WeakCSlot,
    mut recv: tokio::sync::mpsc::UnboundedReceiver<TaskMsg>,
) {
    while let Some(task_msg) = recv.recv().await {
        match task_msg {
            TaskMsg::NewWs { uniq, index, ws, ip, pk } => {
                tokio::select! {
                    task_msg = recv.recv() => {
                        match task_msg {
                            None => break,
                            Some(TaskMsg::Close) => (),
                            _ => unreachable!(),
                        }
                    },
                    _ = ws_task(
                        &ip_deny,
                        &ip_rate,
                        &weak,
                        index,
                        ws,
                        ip,
                        pk,
                    ) => (),
                }
                if let Some(cslot) = weak.upgrade() {
                    cslot.remove(uniq, index);
                }
            }
            _ => unreachable!(),
        }
    }
}

async fn ws_task(
    ip_deny: &ip_deny::IpDeny,
    ip_rate: &ip_rate::IpRate,
    weak: &WeakCSlot,
    index: usize,
    ws: Arc<ws::WebSocket<MaybeTlsStream>>,
    ip: Arc<std::net::Ipv6Addr>,
    pk: PubKey,
) {
    while let Ok(mut payload) = ws.recv().await {
        if !ip_rate.is_ok(*ip, payload.len()) {
            ip_deny.block(*ip).await.unwrap();
            break;
        }

        if payload.len() < 32 {
            break;
        }

        const KEEPALIVE: &[u8; 32] = &[0; 32];

        let dest = {
            let payload = payload.to_mut();

            if &payload[..32] == KEEPALIVE {
                // TODO - keepalive
                continue;
            }

            if &payload[..32] == &pk.0[..] {
                // no self-sends
                break;
            }

            let mut dest = [0; 32];
            dest.copy_from_slice(&payload[..32]);
            let dest = PubKey(Arc::new(dest));

            payload[..32].copy_from_slice(&pk.0[..]);

            dest
        };

        if let Some(cslot) = weak.upgrade() {
            let _ = cslot.send(&dest, payload).await;
        } else {
            break;
        }
    }
}
