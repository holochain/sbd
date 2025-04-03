use crate::*;

/// Secret stream encryptor.
pub struct Encryptor {
    sk: sodoken::SizedLockedArray<32>,
    state: sodoken::secretstream::State,
}

impl Encryptor {
    /// Initialize a new encryptor.
    fn init(&mut self) -> Result<[u8; 24]> {
        let mut header = [0; 24];
        sodoken::secretstream::init_push(
            &mut self.state,
            &mut header,
            &self.sk.lock(),
        )?;
        Ok(header)
    }

    /// Encrypt a new message. This version saves a copy by putting the
    /// encrypted data directly into a protocol message.
    pub fn encrypt(
        &mut self,
        pub_key: &[u8],
        msg: &[u8],
    ) -> Result<protocol::Protocol> {
        let mut out = bytes::BytesMut::zeroed(
            32 + 1 + msg.len() + sodoken::secretstream::ABYTES,
        );
        out[..32].copy_from_slice(&pub_key[..32]);
        out[32] = protocol::T_MESSAGE;

        sodoken::secretstream::push(
            &mut self.state,
            &mut out[33..],
            msg,
            None,
            sodoken::secretstream::Tag::Message,
        )?;

        // unwrap okay since we are constructing this
        Ok(protocol::Protocol::from_full(out.freeze()).unwrap())
    }
}

/// Secret stream decryptor.
pub struct Decryptor {
    state: sodoken::secretstream::State,
}

impl Decryptor {
    /// Decrypt a new message into [bytes::Bytes].
    pub fn decrypt(&mut self, msg: &[u8]) -> Result<bytes::Bytes> {
        let mut out =
            bytes::BytesMut::zeroed(msg.len() - sodoken::secretstream::ABYTES);
        sodoken::secretstream::pull(&mut self.state, &mut out[..], msg, None)?;
        Ok(out.freeze())
    }
}

/// Crypto based on sodoken(libsodium).
pub struct SodokenCrypto {
    sign_pk: [u8; 32],
    sign_sk: Mutex<sodoken::SizedLockedArray<64>>,
    enc_pk: [u8; 32],
    enc_sk: Mutex<sodoken::SizedLockedArray<32>>,
}

impl SodokenCrypto {
    /// Construct a new crypto instance.
    pub fn new() -> Result<Self> {
        loop {
            let mut sign_pk = [0; 32];
            let mut sign_sk = sodoken::SizedLockedArray::new()?;

            sodoken::sign::keypair(&mut sign_pk, &mut sign_sk.lock())?;

            if sign_pk[..28] == [0; 28] {
                continue;
            }

            let mut enc_pk = [0; 32];
            sodoken::sign::pk_to_curve25519(&mut enc_pk, &sign_pk)?;

            let mut enc_sk = sodoken::SizedLockedArray::new()?;
            sodoken::sign::sk_to_curve25519(
                &mut enc_sk.lock(),
                &sign_sk.lock(),
            )?;

            return Ok(Self {
                sign_pk,
                sign_sk: Mutex::new(sign_sk),
                enc_pk,
                enc_sk: Mutex::new(enc_sk),
            });
        }
    }

    fn session(
        &self,
        peer_sign_pk: &[u8; 32],
    ) -> Result<(sodoken::SizedLockedArray<32>, sodoken::SizedLockedArray<32>)>
    {
        let mut peer_enc_pk = [0; 32];
        sodoken::sign::pk_to_curve25519(&mut peer_enc_pk, peer_sign_pk)?;

        let mut rx = sodoken::SizedLockedArray::new()?;
        let mut tx = sodoken::SizedLockedArray::new()?;

        if peer_enc_pk > self.enc_pk {
            sodoken::kx::client_session_keys(
                &mut rx.lock(),
                &mut tx.lock(),
                &self.enc_pk,
                &self.enc_sk.lock().unwrap().lock(),
                &peer_enc_pk,
            )?;
        } else {
            sodoken::kx::server_session_keys(
                &mut rx.lock(),
                &mut tx.lock(),
                &self.enc_pk,
                &self.enc_sk.lock().unwrap().lock(),
                &peer_enc_pk,
            )?;
        }

        Ok((rx, tx))
    }

    /// Construct a new encryptor for a peer connection.
    pub fn new_enc(
        &self,
        peer_sign_pk: &[u8; 32],
    ) -> Result<(Encryptor, [u8; 24])> {
        let (_rx, tx) = self.session(peer_sign_pk)?;

        let mut enc = Encryptor {
            sk: tx,
            state: sodoken::secretstream::State::default(),
        };

        let hdr = enc.init()?;

        Ok((enc, hdr))
    }

    /// Construct a new decryptor for a peer connection.
    pub fn new_dec(
        &self,
        peer_sign_pk: &[u8],
        hdr: &[u8],
    ) -> Result<Decryptor> {
        let mut pk = [0; 32];
        pk.copy_from_slice(&peer_sign_pk[..32]);
        let (mut rx, _tx) = self.session(&pk)?;

        let mut state = sodoken::secretstream::State::default();

        let mut header = [0; 24];
        header.copy_from_slice(&hdr[..24]);

        sodoken::secretstream::init_pull(&mut state, &header, &rx.lock())?;

        Ok(Decryptor { state })
    }
}

impl sbd_client::Crypto for SodokenCrypto {
    fn pub_key(&self) -> &[u8; 32] {
        &self.sign_pk
    }

    fn sign(&self, nonce: &[u8]) -> Result<[u8; 64]> {
        let mut sig = [0; 64];
        sodoken::sign::sign_detached(
            &mut sig,
            nonce,
            &self.sign_sk.lock().unwrap().lock(),
        )?;
        Ok(sig)
    }
}
