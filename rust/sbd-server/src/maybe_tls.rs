//! taken and altered from tokio_tungstenite

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
    pub async fn tls(
        cert: &std::path::Path,
        pk: &std::path::Path,
        tcp: tokio::net::TcpStream,
    ) -> std::io::Result<Self> {
        use rustls_pemfile::Item::*;

        let cert = tokio::fs::read(cert).await?;
        let pk = tokio::fs::read(pk).await?;

        let cert = match rustls_pemfile::read_one_from_slice(&cert) {
            Ok(Some((X509Certificate(cert), _))) => cert,
            _ => return Err(std::io::Error::other("error reading tls cert")),
        };
        let pk = match rustls_pemfile::read_one_from_slice(&pk) {
            Ok(Some((Pkcs1Key(pk), _))) => {
                rustls::pki_types::PrivateKeyDer::Pkcs1(pk)
            }
            Ok(Some((Sec1Key(pk), _))) => {
                rustls::pki_types::PrivateKeyDer::Sec1(pk)
            }
            Ok(Some((Pkcs8Key(pk), _))) => {
                rustls::pki_types::PrivateKeyDer::Pkcs8(pk)
            }
            _ => return Err(std::io::Error::other("error reading priv key")),
        };

        let c = std::sync::Arc::new(
            rustls::server::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], pk)
                .map_err(std::io::Error::other)?,
        );

        let tls = tokio_rustls::TlsAcceptor::from(c).accept(tcp).await?;

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
