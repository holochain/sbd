use crate::*;

const F_KEEPALIVE: &[u8] = b"keep";
const F_LIMIT_BYTE_NANOS: &[u8] = b"lbrt";
const F_LIMIT_IDLE_MILLIS: &[u8] = b"lidl";
const F_AUTH_REQ: &[u8] = b"areq";
const F_AUTH_RES: &[u8] = b"ares";

/// defined by ed25519 spec
const PK_SIZE: usize = 32;

/// defined by ed25519 spec
const SIG_SIZE: usize = 64;

/// sbd spec defines headers to be the same size as ed25519 pub keys
const HDR_SIZE: usize = PK_SIZE;

/// defined by sbd spec
const NONCE_SIZE: usize = 32;

/// defined by sbd spec
pub(crate) const CMD_PREFIX: &[u8; 28] = &[0; 28];

/// Sbd commands.
/// Enum variants represent only the types that clients can send to the server:
/// - not-cmd Message(payload)
/// - `keep` Keepalive
/// - `ares` AuthRes(signature)
/// - other-cmd Unknown
/// Member functions represent only the types that the server can send to the
/// clients:
/// - `lbrt` limit_byte_nanos(i32)
/// - `lidl` limit_idle_millis(i32)
/// - `areq` auth_req(nonce)
/// - `srdy` ready()
pub enum SbdCmd<'c> {
    Message(Payload<'c>),
    Keepalive,
    AuthRes([u8; SIG_SIZE]),
    Unknown,
}

impl<'c> SbdCmd<'c> {
    pub fn parse(payload: Payload<'c>) -> Result<Self> {
        if payload.as_ref().len() < HDR_SIZE {
            return Err(Error::other("invalid payload length"));
        }
        if &payload.as_ref()[..28] == CMD_PREFIX {
            // only include the messages that clients should send
            // mark everything else as Unknown
            match &payload.as_ref()[28..32] {
                F_KEEPALIVE => Ok(SbdCmd::Keepalive),
                F_AUTH_RES => {
                    if payload.as_ref().len() != HDR_SIZE + SIG_SIZE {
                        return Err(Error::other("invalid auth res length"));
                    }
                    let mut sig = [0; SIG_SIZE];
                    sig.copy_from_slice(&payload.as_ref()[HDR_SIZE..]);
                    Ok(SbdCmd::AuthRes(sig))
                }
                _ => Ok(SbdCmd::Unknown),
            }
        } else {
            Ok(SbdCmd::Message(payload))
        }
    }
}

impl SbdCmd<'_> {
    pub fn limit_byte_nanos(limit_byte_nanos: i32) -> Payload<'static> {
        let mut out = Vec::with_capacity(HDR_SIZE + 4);
        let n = limit_byte_nanos.to_be_bytes();
        out.extend_from_slice(CMD_PREFIX);
        out.extend_from_slice(F_LIMIT_BYTE_NANOS);
        out.extend_from_slice(&n[..]);
        Payload::Vec(out)
    }

    pub fn limit_idle_millis(limit_idle_millis: i32) -> Payload<'static> {
        let mut out = Vec::with_capacity(HDR_SIZE + 4);
        let n = limit_idle_millis.to_be_bytes();
        out.extend_from_slice(CMD_PREFIX);
        out.extend_from_slice(F_LIMIT_IDLE_MILLIS);
        out.extend_from_slice(&n[..]);
        Payload::Vec(out)
    }

    pub fn auth_req(nonce: &[u8; 32]) -> Payload<'static> {
        let mut out = Vec::with_capacity(HDR_SIZE + NONCE_SIZE);
        out.extend_from_slice(CMD_PREFIX);
        out.extend_from_slice(F_AUTH_REQ);
        out.extend_from_slice(&nonce[..]);
        Payload::Vec(out)
    }

    pub fn ready() -> Payload<'static> {
        Payload::Slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, b's', b'r', b'd', b'y',
        ])
    }
}
