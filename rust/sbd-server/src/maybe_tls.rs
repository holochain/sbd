//! taken and altered from tokio_tungstenite

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// RustTLS config plus cert and pk paths.
pub struct TlsConfig {
    cert: std::path::PathBuf,
    pk: std::path::PathBuf,
    config: Arc<Mutex<Arc<rustls::server::ServerConfig>>>,
}

impl TlsConfig {
    /// Load a new TlsConfig from a cert and pk path.
    pub async fn new(
        cert: &std::path::Path,
        pk: &std::path::Path,
    ) -> std::io::Result<Self> {
        let cert = cert.to_owned();
        let pk = pk.to_owned();
        let config = Self::load(&cert, &pk).await?;
        Ok(Self {
            cert,
            pk,
            config: Arc::new(Mutex::new(config)),
        })
    }

    /// Get the current rustls::server::ServerConfig.
    pub fn config(&self) -> Arc<rustls::server::ServerConfig> {
        self.config.lock().unwrap().clone()
    }

    /// Reload the cert and pk.
    #[allow(dead_code)] // watch reload tls
    pub async fn reload(&self) -> std::io::Result<()> {
        let new_config = Self::load(&self.cert, &self.pk).await?;
        *self.config.lock().unwrap() = new_config;
        Ok(())
    }

    async fn load(
        cert: &std::path::Path,
        pk: &std::path::Path,
    ) -> std::io::Result<Arc<rustls::server::ServerConfig>> {
        let cert = tokio::fs::read(cert).await?;
        let pk = tokio::fs::read(pk).await?;

        let mut certs = Vec::new();
        for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(&cert)) {
            certs.push(cert?);
        }

        let pk = rustls_pemfile::private_key(&mut std::io::Cursor::new(&pk))?
            .ok_or_else(|| {
            std::io::Error::other("error reading priv key")
        })?;

        Ok(std::sync::Arc::new(
            rustls::server::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, pk)
                .map_err(std::io::Error::other)?,
        ))
    }
}

/// A stream that might be protected with TLS.
#[non_exhaustive]
#[derive(Debug)]
pub enum MaybeTlsStream {
    /// Tcp.
    Tcp(tokio::net::TcpStream),

    /// Tls.
    Tls(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
}

impl MaybeTlsStream {
    /// Wrap a TcpStream in a MaybeTlsStream, configuring TLS
    pub async fn tls(
        tls_config: &TlsConfig,
        tcp: tokio::net::TcpStream,
    ) -> std::io::Result<Self> {
        let config = tls_config.config();

        let tls = tokio_rustls::TlsAcceptor::from(config).accept(tcp).await?;

        Ok(Self::Tls(tls))
    }
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Tcp(ref mut s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(ref mut s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            MaybeTlsStream::Tcp(ref mut s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(ref mut s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            MaybeTlsStream::Tcp(ref mut s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(ref mut s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            MaybeTlsStream::Tcp(ref mut s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(ref mut s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
