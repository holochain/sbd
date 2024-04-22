//! Sbd end to end encryption client.
#[deny(missing_docs)]
use std::io::Result;
use std::sync::Mutex;

pub struct SodokenCrypto {
    sign_pk: [u8; 32],
    sign_sk: Mutex<sodoken::LockedArray<64>>,
}

impl SodokenCrypto {
    pub fn new() -> Result<Self> {
        let mut sign_pk = [0; 32];
        let mut sign_sk = sodoken::LockedArray::new()?;

        sodoken::sign::keypair(&mut sign_pk, &mut sign_sk.lock())?;

        Ok(Self {
            sign_pk,
            sign_sk: Mutex::new(sign_sk),
        })
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
