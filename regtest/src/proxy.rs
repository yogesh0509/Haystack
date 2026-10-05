//! A byte-counting TCP relay between the client and electrs, for the bandwidth measurement
//! (`docs/07-walkthrough.md`, case 10). It counts application bytes in each direction. It doesn't
//! count TCP/IP headers, and regtest has no TLS, which a public server adds on top.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

pub struct CountingProxy {
    addr: SocketAddr,
    sent: Arc<AtomicU64>,
    received: Arc<AtomicU64>,
}

impl CountingProxy {
    /// Listens on a free local port and relays every connection to `upstream` (`host:port`).
    pub fn start(upstream: &str) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let (sent, received) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let (up, s, r) = (upstream.to_string(), sent.clone(), received.clone());
        thread::spawn(move || {
            for client in listener.incoming().flatten() {
                let Ok(server) = TcpStream::connect(&up) else {
                    continue;
                };
                let (Ok(c2), Ok(s2)) = (client.try_clone(), server.try_clone()) else {
                    continue;
                };
                relay(client, server, s.clone());
                relay(s2, c2, r.clone());
            }
        });
        Ok(Self {
            addr,
            sent,
            received,
        })
    }

    /// The address to give `electrum_client::Client::new`.
    pub fn url(&self) -> String {
        self.addr.to_string()
    }

    /// Bytes (client to server, server to client) since the last call. Every byte of a finished
    /// sync is counted before the client sees it, so calling this after `full_scan` returns is exact.
    pub fn take(&self) -> (u64, u64) {
        (
            self.sent.swap(0, Ordering::SeqCst),
            self.received.swap(0, Ordering::SeqCst),
        )
    }
}

fn relay(mut from: TcpStream, mut to: TcpStream, counter: Arc<AtomicU64>) {
    thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match from.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    counter.fetch_add(n as u64, Ordering::SeqCst);
                    if to.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = to.shutdown(Shutdown::Write);
    });
}
