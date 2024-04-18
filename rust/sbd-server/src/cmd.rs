use crate::*;

const F_KEEPALIVE: &[u8] = b"keep";
const F_LIMIT_BYTE_NANOS: &[u8] = b"lbrt";
const F_LIMIT_IDLE_MILLIS: &[u8] = b"lidl";
const F_AUTH_REQ: &[u8] = b"areq";
const F_AUTH_RES: &[u8] = b"ares";
//const F_READY: &[u8] = b"srdy";

/// Sbd commands. This enum only includes the types that clients send.
/// The class contains only methods for generating commands that can
/// be sent to the client.
pub enum SbdCmd<'c> {
    Message(Payload<'c>),
    Keepalive,
    //LimitByteNanos(i32),
    //LimitIdleMillis(i32),
    //AuthReq([u8; 32]),
    AuthRes([u8; 64]),
    //Ready,
    Unknown,
}

const CMD_FLAG: &[u8; 28] = &[0; 28];

impl<'c> SbdCmd<'c> {
    pub fn parse(payload: Payload<'c>) -> Result<Self> {
        if payload.as_ref().len() < 32 {
            return Err(Error::other("invalid payload length"));
        }
        if &payload.as_ref()[..28] == CMD_FLAG {
            // only include the messages that clients should send
            // mark everything else as Unknown
            match &payload.as_ref()[28..32] {
                F_KEEPALIVE => Ok(SbdCmd::Keepalive),
                F_AUTH_RES => {
                    if payload.as_ref().len() != 32 + 64 {
                        return Err(Error::other("invalid auth res length"));
                    }
                    let mut sig = [0; 64];
                    sig.copy_from_slice(&payload.as_ref()[32..]);
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
        let mut out = Vec::with_capacity(32 + 4);
        let n = limit_byte_nanos.to_be_bytes();
        out.extend_from_slice(CMD_FLAG);
        out.extend_from_slice(F_LIMIT_BYTE_NANOS);
        out.extend_from_slice(&n[..]);
        Payload::Vec(out)
    }

    pub fn limit_idle_millis(limit_idle_millis: i32) -> Payload<'static> {
        let mut out = Vec::with_capacity(32 + 4);
        let n = limit_idle_millis.to_be_bytes();
        out.extend_from_slice(CMD_FLAG);
        out.extend_from_slice(F_LIMIT_IDLE_MILLIS);
        out.extend_from_slice(&n[..]);
        Payload::Vec(out)
    }

    pub fn auth_req(nonce: &[u8; 32]) -> Payload<'static> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(CMD_FLAG);
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
