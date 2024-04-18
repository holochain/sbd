//! Attempt to pre-allocate as much as possible, including our tokio tasks.
//! Ideally this would include a frame buffer that we could fill on ws
//! recv and use ase a reference for ws send, but alas, fastwebsockets
//! doesn't seem up to the task. tungstenite will willy-nilly allocate
//! buffers for us, but at least we should only be dealing with one at a
//! time per connection.

use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

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
    handshake_complete: bool,
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

#[derive(Clone)]
pub struct WeakCSlot(Weak<Mutex<CSlotInner>>);

impl WeakCSlot {
    pub fn upgrade(&self) -> Option<CSlot> {
        self.0.upgrade().map(CSlot)
    }
}

pub struct CSlot(Arc<Mutex<CSlotInner>>);

impl CSlot {
    pub fn new(config: Arc<Config>, ip_rate: Arc<ip_rate::IpRate>) -> Self {
        let count = config.limit_clients as usize;
        Self(Arc::new_cyclic(|this| {
            let mut slots = Vec::with_capacity(count);
            let mut task_list = Vec::with_capacity(count);
            for _ in 0..count {
                let (send, recv) = tokio::sync::mpsc::unbounded_channel();
                slots.push(SlotEntry { send });
                task_list.push(tokio::task::spawn(top_task(
                    config.clone(),
                    ip_rate.clone(),
                    WeakCSlot(this.clone()),
                    recv,
                )));
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

    pub fn weak(&self) -> WeakCSlot {
        WeakCSlot(Arc::downgrade(&self.0))
    }

    fn remove(&self, uniq: u64, index: usize) {
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

    // oi clippy, this is super straight forward...
    #[allow(clippy::type_complexity)]
    fn insert_and_get_rate_send_list(
        &self,
        ip: Arc<std::net::Ipv6Addr>,
        pk: PubKey,
        ws: Arc<ws::WebSocket<MaybeTlsStream>>,
    ) -> Option<Vec<(u64, usize, Weak<ws::WebSocket<MaybeTlsStream>>)>> {
        let mut lock = self.0.lock().unwrap();

        if lock.slab.len() >= lock.max_count {
            return None;
        }

        let weak_ws = Arc::downgrade(&ws);

        let uniq = U.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let index = lock.slab.insert(SlabEntry {
            uniq,
            weak_ws,
            handshake_complete: false,
        });

        lock.pk_to_index.insert(pk.clone(), index);

        let rate_send_list = {
            let list = {
                // WARN - allocation here!
                // Also, do we want to limit the max connections from same ip?

                let e = lock
                    .ip_to_index
                    .entry(ip.clone())
                    .or_insert_with(|| Vec::with_capacity(1024));

                e.push(index);

                e.clone()
            };

            let mut rate_send_list = Vec::with_capacity(list.len());

            for index in list.iter() {
                if let Some(slab) = lock.slab.get(*index) {
                    rate_send_list.push((
                        slab.uniq,
                        *index,
                        slab.weak_ws.clone(),
                    ));
                }
            }

            rate_send_list
        };

        let send = lock.slots.get(index).unwrap().send.clone();
        let _ = send.send(TaskMsg::NewWs {
            uniq,
            index,
            ws,
            ip,
            pk,
        });

        Some(rate_send_list)
    }

    pub async fn insert(
        &self,
        ip: Arc<std::net::Ipv6Addr>,
        pk: PubKey,
        ws: Arc<ws::WebSocket<MaybeTlsStream>>,
        limit_ip_byte_nanos: i32,
    ) {
        let rate_send_list = self.insert_and_get_rate_send_list(ip, pk, ws);

        if let Some(rate_send_list) = rate_send_list {
            let mut rate = limit_ip_byte_nanos / rate_send_list.len() as i32;
            if rate < 1 {
                rate = 1;
            }

            for (uniq, index, weak_ws) in rate_send_list {
                if let Some(ws) = weak_ws.upgrade() {
                    if ws
                        .send(cmd::SbdCmd::limit_byte_nanos(rate))
                        .await
                        .is_err()
                    {
                        self.remove(uniq, index);
                    }
                }
            }
        }
    }

    fn mark_ready(&self, uniq: u64, index: usize) {
        let mut lock = self.0.lock().unwrap();
        if let Some(slab) = lock.slab.get_mut(index) {
            if slab.uniq == uniq {
                slab.handshake_complete = true;
            }
        }
    }

    fn get_sender(
        &self,
        pk: &PubKey,
    ) -> Result<(u64, usize, Arc<ws::WebSocket<MaybeTlsStream>>)> {
        let lock = self.0.lock().unwrap();

        let index = match lock.pk_to_index.get(pk) {
            None => return Err(Error::other("no such peer")),
            Some(index) => *index,
        };

        let slab = lock.slab.get(index).unwrap();

        if !slab.handshake_complete {
            return Err(Error::other("no such peer"));
        }

        let uniq = slab.uniq;
        let ws = match slab.weak_ws.upgrade() {
            None => return Err(Error::other("no such peer")),
            Some(ws) => ws,
        };

        Ok((uniq, index, ws))
    }

    async fn send(&self, pk: &PubKey, payload: Payload<'_>) -> Result<()> {
        let (uniq, index, ws) = self.get_sender(pk)?;

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
    config: Arc<Config>,
    ip_rate: Arc<ip_rate::IpRate>,
    weak: WeakCSlot,
    mut recv: tokio::sync::mpsc::UnboundedReceiver<TaskMsg>,
) {
    let mut item = recv.recv().await;
    loop {
        let uitem = match item {
            None => break,
            Some(uitem) => uitem,
        };

        item = if let TaskMsg::NewWs {
            uniq,
            index,
            ws,
            ip,
            pk,
        } = uitem
        {
            let i = tokio::select! {
                i = recv.recv() => i,
                _ = ws_task(
                    &config,
                    &ip_rate,
                    &weak,
                    ws,
                    ip,
                    pk,
                    uniq,
                    index,
                ) => recv.recv().await,
            };
            if let Some(cslot) = weak.upgrade() {
                cslot.remove(uniq, index);
            }
            i
        } else {
            recv.recv().await
        };
    }
}

#[allow(clippy::too_many_arguments)]
async fn ws_task(
    config: &Arc<Config>,
    ip_rate: &ip_rate::IpRate,
    weak_cslot: &WeakCSlot,
    ws: Arc<ws::WebSocket<MaybeTlsStream>>,
    ip: Arc<std::net::Ipv6Addr>,
    pk: PubKey,
    uniq: u64,
    index: usize,
) {
    let auth_res = tokio::time::timeout(config.idle_dur(), async {
        use rand::Rng;
        let mut nonce = [0xdb; 32];
        rand::thread_rng().fill(&mut nonce[..]);

        ws.send(cmd::SbdCmd::auth_req(&nonce)).await?;

        let auth_res = ws.recv().await?;

        if !ip_rate.is_ok(&ip, auth_res.as_ref().len()).await {
            return Err(Error::other("ip rate limited"));
        }

        if let cmd::SbdCmd::AuthRes(sig) = cmd::SbdCmd::parse(auth_res)? {
            if !pk.verify(&sig, &nonce) {
                return Err(Error::other("invalid sig"));
            }
        } else {
            return Err(Error::other("invalid auth response"));
        }

        // NOTE: the byte_nanos limit is sent during the cslot insert

        ws.send(cmd::SbdCmd::limit_idle_millis(config.limit_idle_millis))
            .await?;

        if let Some(cslot) = weak_cslot.upgrade() {
            cslot.mark_ready(uniq, index);
        } else {
            return Err(Error::other("closed"));
        }

        ws.send(cmd::SbdCmd::ready()).await?;

        Ok(())
    })
    .await;

    if auth_res.is_err() {
        return;
    }

    while let Ok(Ok(payload)) =
        tokio::time::timeout(config.idle_dur(), ws.recv()).await
    {
        if !ip_rate.is_ok(&ip, payload.len()).await {
            break;
        }

        let cmd = match cmd::SbdCmd::parse(payload) {
            Err(_) => break,
            Ok(cmd) => cmd,
        };

        match cmd {
            cmd::SbdCmd::Keepalive => (),
            cmd::SbdCmd::AuthRes(_) => break,
            cmd::SbdCmd::Unknown => (),
            cmd::SbdCmd::Message(mut payload) => {
                let dest = {
                    let payload = payload.to_mut();

                    let mut dest = [0; 32];
                    dest.copy_from_slice(&payload[..32]);
                    let dest = PubKey(Arc::new(dest));

                    payload[..32].copy_from_slice(&pk.0[..]);

                    dest
                };

                if let Some(cslot) = weak_cslot.upgrade() {
                    let _ = cslot.send(&dest, payload).await;
                } else {
                    break;
                }
            }
        }
    }
}
