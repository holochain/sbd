//! This adds end-to-end encryption for peer communications over the base
//! sbd communication protocol via
//! [libsodium secretstream](https://doc.libsodium.org/secret-key_cryptography/secretstream).
//!
//! ## Message Type Header
//!
//! Adds a single-byte header to messages sent.
//!
//! Messages with bytes other than the following three should be ignored
//! for future compatibility.
//!
//! - `0x10` - NewStream -- must be followed by 24 byte secret stream header.
//! - `0x11` - Message -- encrypted message including abytes.
//! - `0x12` - RequestNewStream -- only this single byte.
//!
//! ## Message Type Handling
//!
//! - When sending a message to a new (or not recent) peer, clients MUST
//!   establish a new outgoing (encryption) secret stream state and send the
//!   24 byte header in a "NewStream" message.
//! - On receiving a "RequestNewStream" message, clients MUST establish a
//!   new outgoing (encryption) secret stream state and send the 24 byte header
//!   in a "NewStream" message.
//! - On receiving a "NewStream" message, clients MUST establish a new incoming
//!   (decryption) secret stream state.
//! - On receiving a "Message" that cannot be decrypted, clients MUST
//!   (1) ignore the message, (2) delete any incoming (decryption) state, and
//!   (3) send a "RequestNewStream" message. Any message receipt tracking or
//!   re-requesting will not be handled by this library, but may be added by
//!   implementors as a layer on top of this.

/// Start a new stream.
pub const T_NEW_STREAM: u8 = 0x10;

/// Encrypted stream message.
pub const T_MESSAGE: u8 = 0x11;

/// Request start of new stream.
pub const T_REQ_NEW_STREAM: u8 = 0x12;

/// E2e crypto protocol enum.
///
/// The enum variant fields are all shallow clone parts of the "full" field:
/// - `full` the entire message send/recv via sbd-client.
/// - `pub_key` the pub_key peer send/recv to/from.
/// - `base_msg` the base message send/recv to/from the peer.
/// - `...` all additional fields are broken out by enum variant.
#[derive(PartialEq)]
pub enum Protocol {
    /// Message indicating a new stream state should be created
    /// along with the secretstream header for doing so.
    NewStream {
        #[allow(missing_docs)]
        full: bytes::Bytes,
        #[allow(missing_docs)]
        pub_key: bytes::Bytes,
        #[allow(missing_docs)]
        base_msg: bytes::Bytes,
        #[allow(missing_docs)]
        header: bytes::Bytes,
    },

    /// An encrypted message.
    Message {
        #[allow(missing_docs)]
        full: bytes::Bytes,
        #[allow(missing_docs)]
        pub_key: bytes::Bytes,
        #[allow(missing_docs)]
        base_msg: bytes::Bytes,
        #[allow(missing_docs)]
        message: bytes::Bytes,
    },

    /// Request for a new descryption stream state.
    RequestNewStream {
        #[allow(missing_docs)]
        full: bytes::Bytes,
        #[allow(missing_docs)]
        pub_key: bytes::Bytes,
        #[allow(missing_docs)]
        base_msg: bytes::Bytes,
    },
}

impl std::fmt::Debug for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NewStream { .. } => {
                f.debug_struct("Protocol::NewStream").finish()
            }
            Self::Message { .. } => {
                f.debug_struct("Protocol::Message").finish()
            }
            Self::RequestNewStream { .. } => {
                f.debug_struct("Protocol::RequestNewStream").finish()
            }
        }
    }
}

impl Protocol {
    /// Parse a protocol message from complete message bytes.
    /// If None, this message should be ignored.
    pub fn from_full(full: bytes::Bytes) -> Option<Self> {
        if full.len() < 33 {
            return None;
        }
        let pub_key = full.slice(..32);
        let base_msg = full.slice(32..);
        Some(match full[32] {
            T_NEW_STREAM => {
                if base_msg.len() != 25 {
                    return None;
                }
                let header = full.slice(33..);
                Self::NewStream {
                    full,
                    pub_key,
                    base_msg,
                    header,
                }
            }
            T_MESSAGE => {
                let message = full.slice(33..);
                Self::Message {
                    full,
                    pub_key,
                    base_msg,
                    message,
                }
            }
            T_REQ_NEW_STREAM => {
                if base_msg.len() != 1 {
                    return None;
                }
                Self::RequestNewStream {
                    full,
                    pub_key,
                    base_msg,
                }
            }
            _ => return None,
        })
    }

    /// Create a "NewStream" message type.
    /// Panics if the pub_key is not 32 bytes or the header is not 24.
    /// Why not take a `&[u8; N]` you ask? It's just a lot harder to work
    /// with in rust...
    pub fn new_stream(pub_key: &[u8], header: &[u8]) -> Self {
        let mut out = bytes::BytesMut::with_capacity(32 + 1 + 24);
        out.extend_from_slice(&pub_key[..32]);
        out.extend_from_slice(&[T_NEW_STREAM]);
        out.extend_from_slice(&header[..24]);
        // unwrap because we know the content
        Self::from_full(out.freeze()).unwrap()
    }

    /// Create a "Message" message type.
    /// Panics if the pub_key is not 32 bytes.
    /// Why not take a `&[u8; N]` you ask? It's just a lot harder to work
    /// with in rust...
    pub fn message(pub_key: &[u8], message: &[u8]) -> Self {
        let mut out = bytes::BytesMut::with_capacity(32 + 1 + message.len());
        out.extend_from_slice(&pub_key[..32]);
        out.extend_from_slice(&[T_MESSAGE]);
        out.extend_from_slice(message);
        // unwrap because we know the content
        Self::from_full(out.freeze()).unwrap()
    }

    /// Create a "RequestNewStream" message type.
    /// Panics if the pub_key is not 32 bytes.
    /// Why not take a `&[u8; N]` you ask? It's just a lot harder to work
    /// with in rust...
    pub fn request_new_stream(pub_key: &[u8]) -> Self {
        let mut out = bytes::BytesMut::with_capacity(32 + 1);
        out.extend_from_slice(&pub_key[..32]);
        out.extend_from_slice(&[T_REQ_NEW_STREAM]);
        // unwrap because we know the content
        Self::from_full(out.freeze()).unwrap()
    }

    /// Get the full bytes of this protocol message.
    pub fn full(&self) -> &bytes::Bytes {
        match self {
            Self::NewStream { full, .. } => full,
            Self::Message { full, .. } => full,
            Self::RequestNewStream { full, .. } => full,
        }
    }

    /// Get the pub_key bytes of this protocol message.
    pub fn pub_key(&self) -> &bytes::Bytes {
        match self {
            Self::NewStream { pub_key, .. } => pub_key,
            Self::Message { pub_key, .. } => pub_key,
            Self::RequestNewStream { pub_key, .. } => pub_key,
        }
    }

    /// Get the base_msg bytes of this protocol message.
    pub fn base_msg(&self) -> &bytes::Bytes {
        match self {
            Self::NewStream { base_msg, .. } => base_msg,
            Self::Message { base_msg, .. } => base_msg,
            Self::RequestNewStream { base_msg, .. } => base_msg,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const PUB_KEY: &[u8] = &[4; 32];
    const HEADER: &[u8] = &[5; 24];

    #[inline(always)]
    fn valid_roundtrip(orig: &Protocol) {
        let new = Protocol::from_full(orig.full().clone()).unwrap();
        assert_eq!(orig, &new);
        assert_eq!(orig.full(), new.full());
    }

    #[test]
    #[should_panic]
    fn bad_pk_size() {
        Protocol::request_new_stream(&[4; 31]);
    }

    #[test]
    #[should_panic]
    fn bad_hdr_size() {
        Protocol::new_stream(PUB_KEY, &[5; 23]);
    }

    #[test]
    fn other() {
        let mut exp_other = bytes::BytesMut::new();
        exp_other.extend_from_slice(PUB_KEY);
        exp_other.extend_from_slice(&[0x42]);
        exp_other.extend_from_slice(b"not a thing");
        let exp_other = exp_other.freeze();
        assert!(Protocol::from_full(exp_other.clone()).is_none());
    }

    #[test]
    fn new_stream() {
        let ns = Protocol::new_stream(PUB_KEY, HEADER);
        valid_roundtrip(&ns);

        let mut exp_base_msg = Vec::new();
        exp_base_msg.push(T_NEW_STREAM);
        exp_base_msg.extend_from_slice(HEADER);

        assert!(matches!(ns, Protocol::NewStream {
            pub_key,
            base_msg,
            header,
            ..
        } if pub_key.as_ref() == PUB_KEY
            && base_msg.as_ref() == exp_base_msg
            && header.as_ref() == HEADER
        ));
    }

    #[test]
    fn message() {
        let ns = Protocol::message(PUB_KEY, b"hello");
        valid_roundtrip(&ns);

        let mut exp_base_msg = Vec::new();
        exp_base_msg.push(T_MESSAGE);
        exp_base_msg.extend_from_slice(b"hello");

        assert!(matches!(ns, Protocol::Message {
            pub_key,
            base_msg,
            message,
            ..
        } if pub_key.as_ref() == PUB_KEY
            && base_msg.as_ref() == exp_base_msg
            && message.as_ref() == b"hello"
        ));
    }

    #[test]
    fn req_new_stream() {
        let ns = Protocol::request_new_stream(PUB_KEY);
        valid_roundtrip(&ns);

        assert!(matches!(ns, Protocol::RequestNewStream {
            pub_key,
            base_msg,
            ..
        } if pub_key.as_ref() == PUB_KEY && base_msg.as_ref() == [0x12]));
    }
}
