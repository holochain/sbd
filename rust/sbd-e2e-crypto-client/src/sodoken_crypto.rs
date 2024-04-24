use crate::*;

/// Secret stream encryptor.
pub struct Encryptor {
    sk: sodoken::LockedArray<32>,
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

    /// Encrypt a new message.
    pub fn encrypt(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0; msg.len() + sodoken::secretstream::ABYTES];
        sodoken::secretstream::push(
            &mut self.state,
            msg,
            None,
            sodoken::secretstream::Tag::Message,
            &mut out,
        )?;
        Ok(out)
    }
}

/// Secret stream decryptor.
pub struct Decryptor {
    sk: sodoken::LockedArray<32>,
    state: sodoken::secretstream::State,
}

impl Decryptor {
    /// Decrypt a new message.
    pub fn decrypt(&mut self, msg: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut out = vec![0; msg.len() - sodoken::secretstream::ABYTES];
        match sodoken::secretstream::pull(&mut self.state, &mut out, msg, None)
        {
            Ok(_) => return Ok(Some(out)),
            Err(_) => {
                if msg.len() == 24 {
                    let mut header = [0; 24];
                    header.copy_from_slice(msg);
                    if sodoken::secretstream::init_pull(
                        &mut self.state,
                        &header,
                        &self.sk.lock(),
                    )
                    .is_ok()
                    {
                        return Ok(None);
                    }
                }
            }
        }
        Err(Error::other("decryption failure"))
    }
}

/// Crypto based on sodoken(libsodium).
pub struct SodokenCrypto {
    sign_pk: [u8; 32],
    sign_sk: Mutex<sodoken::LockedArray<64>>,
    enc_pk: [u8; 32],
    enc_sk: Mutex<sodoken::LockedArray<32>>,
}

impl SodokenCrypto {
    /// Construct a new crypto instance.
    pub fn new() -> Result<Self> {
        loop {
            let mut sign_pk = [0; 32];
            let mut sign_sk = sodoken::LockedArray::new()?;

            sodoken::sign::keypair(&mut sign_pk, &mut sign_sk.lock())?;

            if sign_pk[..28] == [0; 28] {
                continue;
            }

            let mut enc_pk = [0; 32];
            sodoken::sign::pk_to_curve25519(&mut enc_pk, &sign_pk)?;

            let mut enc_sk = sodoken::LockedArray::new()?;
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

    /// Construct a new encryption / decryption pair for given remote peer.
    pub fn new_enc(
        &self,
        peer_sign_pk: &[u8; 32],
    ) -> Result<(Encryptor, [u8; 24], Decryptor)> {
        let mut peer_enc_pk = [0; 32];
        sodoken::sign::pk_to_curve25519(&mut peer_enc_pk, peer_sign_pk)?;

        let mut rx = sodoken::LockedArray::new()?;
        let mut tx = sodoken::LockedArray::new()?;

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

        let mut enc = Encryptor {
            sk: tx,
            state: sodoken::secretstream::State::default(),
        };

        let hdr = enc.init()?;

        Ok((
            enc,
            hdr,
            Decryptor {
                sk: rx,
                state: sodoken::secretstream::State::default(),
            },
        ))
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
