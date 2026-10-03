//! The connection to the Electrum server: TCP, or TLS with trust on first use, counting every byte.
//!
//! `electrum-client` 0.24.1 offers two TLS modes: check the certificate against the public
//! authorities, or check nothing at all (`validate_domain(false)` accepts any certificate and any
//! handshake signature). Most public Electrum servers are self-signed, so the first mode refuses
//! them and the second protects against nobody. This module adds the policy Electrum's own client
//! uses: trust a certificate the first time, and refuse a different one afterwards.
//!
//! It uses OpenSSL rather than rustls because rustls verifies handshake signatures through webpki,
//! which accepts only version 3 certificates. A survey of Electrum's public server list on
//! 2026-10-02 found 7 of the 37 reachable servers on version 1 certificates, `fortress.qtornado.com`
//! among them (`docs/04-roadmap.md`, Week 4).
//!
//! The policy, per `host:port`, with the pins kept in a JSON file:
//! - no pin yet: accept, and pin the certificate's SHA-256 together with whether the public
//!   authorities vouched for it;
//! - the authorities vouch for it now: accept, and update the pin (authority-signed certificates
//!   are renewed every few months);
//! - otherwise: accept only the pinned certificate. A server first seen with an authority-signed
//!   certificate that now presents a self-signed one is refused, since that is what an attacker in
//!   the middle would present.
//!
//! The handshake proves the server holds the key of the certificate it presented: OpenSSL checks
//! the handshake signature against it whatever the certificate check says. The policy runs after
//! the handshake and before any Electrum request is written.

use std::borrow::Borrow;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use bdk_wallet::bitcoin::{Script, Txid};
use electrum_client::raw_client::RawClient;
use electrum_client::{
    Batch, ElectrumApi, Error, GetBalanceRes, GetHeadersRes, GetHistoryRes, GetMerkleRes,
    ListUnspentRes, Param, RawHeaderNotification, ScriptStatus, ServerFeaturesRes, TxidFromPosRes,
};
use openssl::hash::MessageDigest;
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
use openssl::x509::X509VerifyResult;
use serde_json::{json, Map, Value};

const TIMEOUT: Duration = Duration::from_secs(30);

/// Bytes in each direction, shared between a stream and whoever reads the totals.
#[derive(Debug, Default, Clone)]
pub struct Counter {
    pub sent: Arc<AtomicU64>,
    pub received: Arc<AtomicU64>,
}

impl Counter {
    pub fn totals(&self) -> (u64, u64) {
        (
            self.sent.load(Ordering::SeqCst),
            self.received.load(Ordering::SeqCst),
        )
    }
}

/// A TCP stream that counts what crosses it. Under TLS it sits below the encryption, so it counts
/// the bytes on the wire, TLS included.
#[derive(Debug)]
pub struct Counting {
    inner: TcpStream,
    counter: Counter,
}

impl Read for Counting {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.counter.received.fetch_add(n as u64, Ordering::SeqCst);
        Ok(n)
    }
}

impl Write for Counting {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.counter.sent.fetch_add(n as u64, Ordering::SeqCst);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// What the certificate policy decided for a TLS connection, for the page to show.
#[derive(Debug, Clone)]
pub struct CertStatus {
    pub fingerprint: String,
    pub authority_signed: bool,
    pub decision: &'static str,
}

/// Either kind of connection, as one `ElectrumApi` client.
pub enum Client {
    Tcp(RawClient<Counting>),
    Tls(RawClient<SslStream<Counting>>),
}

/// A parsed `tcp://host:port` or `ssl://host:port`.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub tls: bool,
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn parse(url: &str) -> anyhow::Result<Self> {
        let (tls, rest) = match url.split_once("://") {
            Some(("tcp", rest)) => (false, rest),
            Some(("ssl", rest)) => (true, rest),
            Some((scheme, _)) => bail!("unknown scheme {scheme}: use tcp:// or ssl://"),
            None => (false, url),
        };
        let (host, port) = rest
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("{url} has no port"))?;
        // electrs listens on 0.0.0.0; connect to it on the loopback address.
        let host = if host == "0.0.0.0" { "127.0.0.1" } else { host };
        Ok(Self {
            tls,
            host: host.to_string(),
            port: port.parse().context("port")?,
        })
    }

    /// The honeypot and regtest's electrs: the only servers a plain, unpadded sync may go to.
    pub fn is_local(&self) -> bool {
        matches!(self.host.as_str(), "127.0.0.1" | "localhost" | "::1")
    }

    pub fn key(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn url(&self) -> String {
        format!("{}://{}", if self.tls { "ssl" } else { "tcp" }, self.key())
    }
}

/// Opens a new connection: one per sync, so each sync is its own session on the server.
pub fn connect(
    endpoint: &Endpoint,
    pins: &PinFile,
    counter: Counter,
) -> anyhow::Result<(Client, Option<CertStatus>)> {
    let addr = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("{} has no address", endpoint.key()))?;
    let tcp = TcpStream::connect_timeout(&addr, TIMEOUT)
        .with_context(|| format!("connecting to {}", endpoint.key()))?;
    tcp.set_read_timeout(Some(TIMEOUT))?;
    tcp.set_write_timeout(Some(TIMEOUT))?;
    let stream = Counting {
        inner: tcp,
        counter,
    };
    if !endpoint.tls {
        return Ok((hello(Client::Tcp(RawClient::from(stream)))?, None));
    }

    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    // Finish the handshake whatever the certificate check says; the policy below decides.
    builder.set_verify(SslVerifyMode::NONE);
    let tls = builder
        .build()
        .configure()?
        .connect(&endpoint.host, stream)
        .map_err(|e| anyhow!("TLS handshake with {} failed: {e}", endpoint.key()))?;
    let cert = tls
        .ssl()
        .peer_certificate()
        .ok_or_else(|| anyhow!("{} presented no certificate", endpoint.key()))?;
    let fingerprint = hex(&cert.digest(MessageDigest::sha256())?);
    // Chain to a public authority and match the host name, as a browser would require.
    let authority_signed = tls.ssl().verify_result() == X509VerifyResult::OK;
    let decision = pins.check(&endpoint.key(), &fingerprint, authority_signed)?;
    Ok((
        hello(Client::Tls(RawClient::from(tls)))?,
        Some(CertStatus {
            fingerprint,
            authority_signed,
            decision,
        }),
    ))
}

/// Electrum's `server.version` handshake. ElectrumX and Fulcrum refuse every other request until
/// a client sends it, and `electrum-client` never does. The client name is left empty, so it says
/// nothing about which wallet software is asking; 1.4 is the protocol version every common server
/// speaks.
fn hello(client: Client) -> anyhow::Result<Client> {
    client
        .raw_call(
            "server.version",
            [Param::String(String::new()), Param::String("1.4".into())],
        )
        .context("server.version")?;
    Ok(client)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The pinned certificates, one JSON object keyed by `host:port`.
pub struct PinFile {
    path: PathBuf,
}

impl PinFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn load(&self) -> anyhow::Result<Map<String, Value>> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => Ok(serde_json::from_str(&text)?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Map::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// Applies the policy in the module comment; an error means the connection must not be used.
    pub fn check(
        &self,
        server: &str,
        fingerprint: &str,
        authority_signed: bool,
    ) -> anyhow::Result<&'static str> {
        let mut pins = self.load()?;
        let pinned = pins.get(server).cloned();
        let decision = match &pinned {
            None => "trusted on first use and pinned",
            Some(_) if authority_signed => "signed by a public authority",
            Some(p) if p["sha256"].as_str() == Some(fingerprint) => {
                "matches the pinned certificate"
            }
            Some(p) if p["authority_signed"].as_bool() == Some(true) => bail!(
                "{server} was authority-signed when first seen and now presents a certificate no \
                 authority vouches for ({fingerprint}); refusing"
            ),
            Some(p) => bail!(
                "{server} presented certificate {fingerprint}, but {} is pinned; refusing",
                p["sha256"].as_str().unwrap_or("?")
            ),
        };
        if pinned.as_ref().and_then(|p| p["sha256"].as_str()) != Some(fingerprint) {
            pins.insert(
                server.to_string(),
                json!({ "sha256": fingerprint, "authority_signed": authority_signed }),
            );
            let tmp = self.path.with_extension("tmp");
            std::fs::write(&tmp, serde_json::to_string_pretty(&pins)? + "\n")?;
            std::fs::rename(&tmp, &self.path)?;
        }
        Ok(decision)
    }
}

/// Forwards every `ElectrumApi` call to whichever connection this is.
macro_rules! forward {
    ($($name:ident ( $($arg:ident : $ty:ty),* ) -> $ret:ty;)*) => {
        $(fn $name(&self, $($arg: $ty),*) -> $ret {
            match self {
                Client::Tcp(c) => c.$name($($arg),*),
                Client::Tls(c) => c.$name($($arg),*),
            }
        })*
    };
}

impl ElectrumApi for Client {
    fn raw_call(
        &self,
        method_name: &str,
        params: impl IntoIterator<Item = Param>,
    ) -> Result<serde_json::Value, Error> {
        match self {
            Client::Tcp(c) => c.raw_call(method_name, params),
            Client::Tls(c) => c.raw_call(method_name, params),
        }
    }

    fn batch_script_get_history<'s, I>(&self, scripts: I) -> Result<Vec<Vec<GetHistoryRes>>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        match self {
            Client::Tcp(c) => c.batch_script_get_history(scripts),
            Client::Tls(c) => c.batch_script_get_history(scripts),
        }
    }

    fn batch_transaction_get_raw<'t, I>(&self, txids: I) -> Result<Vec<Vec<u8>>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'t Txid>,
    {
        match self {
            Client::Tcp(c) => c.batch_transaction_get_raw(txids),
            Client::Tls(c) => c.batch_transaction_get_raw(txids),
        }
    }

    fn batch_script_subscribe<'s, I>(&self, scripts: I) -> Result<Vec<Option<ScriptStatus>>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        match self {
            Client::Tcp(c) => c.batch_script_subscribe(scripts),
            Client::Tls(c) => c.batch_script_subscribe(scripts),
        }
    }

    fn batch_script_get_balance<'s, I>(&self, scripts: I) -> Result<Vec<GetBalanceRes>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        match self {
            Client::Tcp(c) => c.batch_script_get_balance(scripts),
            Client::Tls(c) => c.batch_script_get_balance(scripts),
        }
    }

    fn batch_script_list_unspent<'s, I>(
        &self,
        scripts: I,
    ) -> Result<Vec<Vec<ListUnspentRes>>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        match self {
            Client::Tcp(c) => c.batch_script_list_unspent(scripts),
            Client::Tls(c) => c.batch_script_list_unspent(scripts),
        }
    }

    fn batch_block_header_raw<I>(&self, heights: I) -> Result<Vec<Vec<u8>>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<u32>,
    {
        match self {
            Client::Tcp(c) => c.batch_block_header_raw(heights),
            Client::Tls(c) => c.batch_block_header_raw(heights),
        }
    }

    fn batch_estimate_fee<I>(&self, numbers: I) -> Result<Vec<f64>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<usize>,
    {
        match self {
            Client::Tcp(c) => c.batch_estimate_fee(numbers),
            Client::Tls(c) => c.batch_estimate_fee(numbers),
        }
    }

    fn batch_transaction_get_merkle<I>(
        &self,
        txids_and_heights: I,
    ) -> Result<Vec<GetMerkleRes>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<(Txid, usize)>,
    {
        match self {
            Client::Tcp(c) => c.batch_transaction_get_merkle(txids_and_heights),
            Client::Tls(c) => c.batch_transaction_get_merkle(txids_and_heights),
        }
    }

    forward! {
        transaction_get_raw(txid: &Txid) -> Result<Vec<u8>, Error>;
        batch_call(batch: &Batch) -> Result<Vec<serde_json::Value>, Error>;
        block_headers_subscribe_raw() -> Result<RawHeaderNotification, Error>;
        block_headers_pop_raw() -> Result<Option<RawHeaderNotification>, Error>;
        block_header_raw(height: usize) -> Result<Vec<u8>, Error>;
        block_headers(start_height: usize, count: usize) -> Result<GetHeadersRes, Error>;
        estimate_fee(number: usize) -> Result<f64, Error>;
        relay_fee() -> Result<f64, Error>;
        script_subscribe(script: &Script) -> Result<Option<ScriptStatus>, Error>;
        script_unsubscribe(script: &Script) -> Result<bool, Error>;
        script_pop(script: &Script) -> Result<Option<ScriptStatus>, Error>;
        script_get_balance(script: &Script) -> Result<GetBalanceRes, Error>;
        script_get_history(script: &Script) -> Result<Vec<GetHistoryRes>, Error>;
        script_list_unspent(script: &Script) -> Result<Vec<ListUnspentRes>, Error>;
        transaction_broadcast_raw(raw_tx: &[u8]) -> Result<Txid, Error>;
        transaction_get_merkle(txid: &Txid, height: usize) -> Result<GetMerkleRes, Error>;
        txid_from_pos(height: usize, tx_pos: usize) -> Result<Txid, Error>;
        txid_from_pos_with_merkle(height: usize, tx_pos: usize) -> Result<TxidFromPosRes, Error>;
        server_features() -> Result<ServerFeaturesRes, Error>;
        ping() -> Result<(), Error>;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins(name: &str) -> PinFile {
        let path =
            std::env::temp_dir().join(format!("haystack-pins-{}-{name}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        PinFile::new(path)
    }

    #[test]
    fn a_self_signed_certificate_is_pinned_and_a_different_one_refused() {
        let p = pins("self");
        assert_eq!(
            p.check("s:1", "aa", false).unwrap(),
            "trusted on first use and pinned"
        );
        assert_eq!(
            p.check("s:1", "aa", false).unwrap(),
            "matches the pinned certificate"
        );
        assert!(p.check("s:1", "bb", false).is_err());
        // Another server's pin is separate.
        assert!(p.check("t:1", "bb", false).is_ok());
    }

    #[test]
    fn an_authority_signed_server_may_renew_but_not_fall_back_to_self_signed() {
        let p = pins("ca");
        assert!(p.check("s:1", "aa", true).is_ok());
        assert_eq!(
            p.check("s:1", "bb", true).unwrap(),
            "signed by a public authority"
        );
        assert!(p.check("s:1", "cc", false).is_err());
        // The renewed certificate was pinned, so presenting it without authority backing is the
        // same certificate, not a downgrade.
        assert!(p.check("s:1", "bb", false).is_ok());
    }

    #[test]
    fn endpoints_parse_and_only_loopback_is_local() {
        let e = Endpoint::parse("ssl://fortress.qtornado.com:50002").unwrap();
        assert!(e.tls && !e.is_local() && e.port == 50002);
        let r = Endpoint::parse("0.0.0.0:35209").unwrap();
        assert!(!r.tls && r.is_local() && r.host == "127.0.0.1");
        assert!(Endpoint::parse("http://x:1").is_err());
    }
}
