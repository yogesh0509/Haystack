//! `haystack-demo`: the demo wallet behind a local web page.
//!
//! Two copies of one wallet sync side by side against the same server: **plain** (padding 1, the
//! leak itself, allowed only against a local server) and **Haystack** (the dial). After every sync
//! the repo's own attacker scores each copy's session log, and the page shows that score, the
//! funded column beside it, and the bytes the sync cost.
//!
//! `--regtest` runs against a private chain with a paid wallet (a restored wallet's first sync);
//! without it the wallet is the never-paid public-seed demo wallet that `capture/` also scans,
//! watch-only. The automatic sync runs on `SyncTimer`. `demo/README.md` has every flag and the
//! commands for each server.

mod score;
mod transport;
mod wallet;

use std::collections::VecDeque;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail};
use bdk_testenv::bitcoincore_rpc::RpcApi;
use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bdk_wallet::bitcoin::hashes::{sha256, Hash};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{Address, Amount, Network};
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{KeychainKind, Wallet};
use haystack_electrum::key::DecoyKey;
use haystack_electrum::schedule::{SyncTimer, DEFAULT_MEAN};
use haystack_regtest::population::random_history;
use haystack_regtest::{build_history, mine, wait_for_history, TestEnv, DEMO_SEED};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::{json, Value};
use tiny_http::{Header, Method, Response, Server};

use transport::{Endpoint, PinFile};
use wallet::{Descriptors, Files};

const PAGE: &str = include_str!("../index.html");
/// The dial's steps: the settings regtest's session generator trains the structural attacker at.
const PADDINGS: [u32; 4] = [2, 5, 10, 20];
const CHAIN_SHARES: [f64; 3] = [0.0, 0.1, 0.3];
const PLAIN: usize = 0;
const HAYSTACK: usize = 1;

struct Args {
    regtest: bool,
    url: Option<String>,
    host: String,
    port: u16,
    mean: Duration,
    data: PathBuf,
    train: PathBuf,
    padding: u32,
}

fn args() -> anyhow::Result<Args> {
    let root = score::repo_root();
    let mut a = Args {
        regtest: false,
        url: None,
        host: "127.0.0.1".into(),
        port: 7878,
        mean: DEFAULT_MEAN,
        data: root.join("out/demo"),
        train: root.join("out/sessions"),
        padding: 10,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        if flag == "--regtest" {
            a.regtest = true;
            continue;
        }
        let value = it.next().ok_or_else(|| anyhow!("{flag} needs a value"))?;
        match flag.as_str() {
            "--url" => a.url = Some(value),
            "--host" => a.host = value,
            "--port" => a.port = value.parse()?,
            "--mean-minutes" => a.mean = Duration::from_secs_f64(value.parse::<f64>()? * 60.0),
            "--data" => a.data = value.into(),
            "--train" => a.train = value.into(),
            "--padding" => a.padding = value.parse()?,
            _ => bail!("unknown flag {flag}"),
        }
    }
    if a.regtest == a.url.is_some() {
        bail!("pass exactly one of --regtest or --url tcp://host:port | ssl://host:port");
    }
    if !PADDINGS.contains(&a.padding) {
        bail!("--padding must be one of {PADDINGS:?}, the settings the attacker is trained at");
    }
    Ok(a)
}

/// What the wallet is and where it syncs, fixed once the server is known.
#[derive(Clone)]
struct World {
    endpoint: Endpoint,
    descriptors: Descriptors,
    key: DecoyKey,
    public: [String; 2],
}

struct Profile {
    files: Files,
    padding: u32,
    chain_share: f64,
    open: Option<(Connection, wallet::DemoWallet)>,
    view: Value,
}

struct App {
    regtest: bool,
    status: Mutex<String>,
    world: Mutex<Option<World>>,
    env: Mutex<Option<TestEnv>>,
    profiles: [Mutex<Profile>; 2],
    /// Copies of each profile's view, readable while that profile is busy syncing.
    views: Mutex<[Value; 2]>,
    log: Mutex<VecDeque<String>>,
    /// The latest regtest or restore action, so the page can show it where the button was pressed.
    action: Mutex<Value>,
    pins: PinFile,
    train: PathBuf,
    mean: Duration,
    next_auto: Mutex<Option<Instant>>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl App {
    fn say(&self, line: impl Into<String>) {
        let line = line.into();
        eprintln!("{line}");
        let mut log = self.log.lock().unwrap();
        log.push_front(format!("{} {line}", now_unix()));
        log.truncate(200);
    }

    fn world(&self) -> anyhow::Result<World> {
        self.world
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow!("still starting: {}", self.status.lock().unwrap()))
    }

    fn publish(&self, which: usize, view: &Value) {
        self.views.lock().unwrap()[which] = view.clone();
    }
}

/// The never-paid demo wallet `capture/` also scans: watch-only BIP84 descriptors from a public string.
fn capture_wallet() -> anyhow::Result<(Descriptors, Xpub)> {
    let secp = Secp256k1::new();
    let seed = sha256::Hash::hash(b"haystack-capture-demo");
    let master = Xpriv::new_master(Network::Bitcoin, seed.as_byte_array())?;
    let account = Xpub::from_priv(
        &secp,
        &master.derive_priv(&secp, &DerivationPath::from_str("m/84'/0'/0'")?)?,
    );
    let origin = format!("[{}/84'/0'/0']", master.fingerprint(&secp));
    Ok((
        Descriptors {
            external: format!("wpkh({origin}{account}/0/*)"),
            internal: format!("wpkh({origin}{account}/1/*)"),
            network: Network::Bitcoin,
        },
        account,
    ))
}

fn public_descriptors(d: &Descriptors) -> anyhow::Result<[String; 2]> {
    let w = Wallet::create(d.external.clone(), d.internal.clone())
        .network(d.network)
        .create_wallet_no_persist()?;
    Ok([
        w.public_descriptor(KeychainKind::External).to_string(),
        w.public_descriptor(KeychainKind::Internal).to_string(),
    ])
}

/// Starts the regtest chain and gives the wallets their histories, as `sessions.rs` does.
fn build_regtest(app: &App) -> anyhow::Result<World> {
    *app.status.lock().unwrap() = "starting bitcoind and electrs".into();
    let env = haystack_regtest::start().map_err(|e| anyhow!("{e}"))?;
    // Held by the app from here on, so stopping the demo stops both processes.
    *app.env.lock().unwrap() = Some(env);
    let demo = with_env(app, |env| {
        *app.status.lock().unwrap() = "giving the demo wallet its history".into();
        let demo = build_history(env, DEMO_SEED).map_err(|e| anyhow!("{e}"))?;
        mine(env, 20).map_err(|e| anyhow!("{e}"))?;
        let mut rng = StdRng::seed_from_u64(0);
        for i in 0..12 {
            *app.status.lock().unwrap() = format!(
                "giving other wallets their histories, so chain decoys have candidates ({i}/12)"
            );
            random_history(env, &format!("haystack-train-0-{i:02}"), &mut rng)
                .map_err(|e| anyhow!("{e}"))?;
        }
        Ok(demo)
    })?;
    for line in &demo.story {
        app.say(format!("regtest history: {line}"));
    }
    let endpoint = with_env(app, |env| Endpoint::parse(&env.electrsd.electrum_url))?;
    let descriptors = Descriptors {
        external: demo.external.clone(),
        internal: demo.internal.clone(),
        network: Network::Regtest,
    };
    Ok(World {
        endpoint,
        public: public_descriptors(&descriptors)?,
        descriptors,
        key: demo.decoy_key(),
    })
}

fn balance_json(w: &Wallet) -> Value {
    let b = w.balance();
    json!({
        "confirmed": b.confirmed.to_sat(),
        "trusted_pending": b.trusted_pending.to_sat(),
        "untrusted_pending": b.untrusted_pending.to_sat(),
        "immature": b.immature.to_sat(),
        "total": b.total().to_sat(),
    })
}

/// One sync of one profile, with the profile already locked.
fn sync_locked(app: &App, which: usize, p: &mut Profile, trigger: &str) -> anyhow::Result<()> {
    let world = app.world()?;
    let padding = if which == PLAIN { 1 } else { p.padding };
    if padding == 1 && !world.endpoint.is_local() {
        bail!("an unpadded sync sends the leak itself, so it only runs against a local server");
    }
    if p.open.is_none() {
        p.open = Some(wallet::open(&p.files, &world.descriptors)?);
    }
    // Published before the network round, so the page shows the sync while it runs.
    p.view["syncing"] = json!({
        "since": now_unix(), "trigger": trigger, "expect_secs": p.view["last"]["secs"].clone(),
    });
    app.publish(which, &p.view);
    let (db, w) = p.open.as_mut().expect("opened above");
    let started = Instant::now();
    let result = wallet::sync(
        db,
        w,
        &p.files,
        wallet::Haystack {
            endpoint: &world.endpoint,
            pins: &app.pins,
            key: &world.key,
            padding,
            chain_share: if which == PLAIN { 0.0 } else { p.chain_share },
        },
    );
    let secs = started.elapsed().as_secs_f64();
    let name = if which == PLAIN { "plain" } else { "Haystack" };
    p.view["syncing"] = Value::Null;
    let synced = match result {
        Ok(s) => s,
        Err(e) => {
            p.view["last_error"] = json!(e.to_string());
            app.publish(which, &p.view);
            app.say(format!("{name}: {trigger} sync failed: {e}"));
            return Err(e);
        }
    };
    let cert = synced.cert.as_ref().map(|c| {
        json!({ "sha256": c.fingerprint, "authority_signed": c.authority_signed, "decision": c.decision })
    });
    let last = json!({
        "at": now_unix(), "trigger": trigger, "secs": secs, "padding": padding,
        "chain_share": if which == PLAIN { 0.0 } else { p.chain_share },
        "sent": synced.sent, "received": synced.received,
        "queries": synced.queries, "reals": synced.reals, "cert": cert,
    });
    p.view["last_error"] = Value::Null;
    p.view["balance"] = balance_json(w);
    p.view["txs"] = json!(w.transactions().count());
    p.view["utxos"] = json!(w.list_unspent().count());
    p.view["last"] = last.clone();
    p.view["ledger"] = json!(std::fs::read_to_string(&p.files.ledger).unwrap_or_default());
    p.view["scoring"] = json!(true);
    app.publish(which, &p.view);
    app.say(format!(
        "{name}: {trigger} sync sent {} scripthashes ({} real) in {secs:.1} s, {:.1} KiB",
        synced.queries,
        synced.reals,
        (synced.sent + synced.received) as f64 / 1024.0
    ));

    let score = score::score(&p.files.session, &app.train);
    let mut entry = last;
    // The grid's rows are for the latest sync only; the history table keeps the numbers.
    entry["score"] = score::without_view(&score);
    p.view["score"] = score;
    p.view["scoring"] = json!(false);
    p.view["history"]
        .as_array_mut()
        .expect("history is an array")
        .push(entry);
    app.publish(which, &p.view);
    Ok(())
}

fn sync(app: &App, which: usize, trigger: &str) -> anyhow::Result<()> {
    let mut p = app.profiles[which]
        .try_lock()
        .map_err(|_| anyhow!("a sync of this wallet is already running"))?;
    sync_locked(app, which, &mut p, trigger)
}

/// The automatic sync: `SyncTimer` decides when, and a missed or busy due time is skipped.
fn auto_loop(app: Arc<App>) {
    while app.world.lock().unwrap().is_none() {
        std::thread::sleep(Duration::from_millis(500));
    }
    let mut rng = rand::thread_rng();
    let mut timer = SyncTimer::start(app.mean, Instant::now(), &mut rng);
    loop {
        *app.next_auto.lock().unwrap() = Some(timer.due());
        let now = Instant::now();
        if !timer.is_due(now) {
            std::thread::sleep((timer.due() - now).min(Duration::from_secs(1)));
            continue;
        }
        if timer.missed(now) {
            app.say("automatic sync: the process wasn't running when it came due, so it is skipped and the next one drawn from now");
            timer.skip(now, &mut rng);
            continue;
        }
        match app.profiles[HAYSTACK].try_lock() {
            Err(_) => {
                app.say("automatic sync came due during a manual sync: skipped, next one drawn from now");
                timer.skip(now, &mut rng);
            }
            Ok(mut p) => {
                let _ = sync_locked(&app, HAYSTACK, &mut p, "automatic");
                drop(p);
                timer.finished(Instant::now(), &mut rng);
            }
        }
    }
}

fn with_env<T>(app: &App, f: impl FnOnce(&TestEnv) -> anyhow::Result<T>) -> anyhow::Result<T> {
    let env = app.env.lock().unwrap();
    let env = env
        .as_ref()
        .ok_or_else(|| anyhow!("only in --regtest mode"))?;
    f(env)
}

/// Someone pays the Haystack wallet's next unused receive address.
fn pay(app: &App) -> anyhow::Result<String> {
    let world = app.world()?;
    let mut p = app.profiles[HAYSTACK]
        .try_lock()
        .map_err(|_| anyhow!("a sync is running; try again in a moment"))?;
    if p.open.is_none() {
        p.open = Some(wallet::open(&p.files, &world.descriptors)?);
    }
    let (db, w) = p.open.as_mut().expect("opened above");
    let spk = wallet::next_address(db, w)?;
    let address = Address::from_script(&spk, Network::Regtest)?;
    let index = w.derivation_of_spk(spk.clone()).map(|(_, i)| i);
    drop(p);
    with_env(app, |env| {
        let txid = env.send(&address, Amount::from_sat(400_000))?;
        wait_for_history(env, &spk, txid).map_err(|e| anyhow!("{e}"))?;
        Ok(format!(
            "regtest: someone paid 0.004 BTC to external {} ({address}), unconfirmed",
            index.map_or("?".into(), |i| i.to_string())
        ))
    })
}

/// The Haystack wallet pays 0.01 BTC to the node, broadcast through bitcoind, not the sync server.
fn send(app: &App) -> anyhow::Result<String> {
    let mut p = app.profiles[HAYSTACK]
        .try_lock()
        .map_err(|_| anyhow!("a sync is running; try again in a moment"))?;
    let (_, w) = p
        .open
        .as_mut()
        .ok_or_else(|| anyhow!("sync the Haystack wallet first, so it knows its coins"))?;
    with_env(app, |env| {
        let to = env
            .bitcoind
            .client
            .get_new_address(None, None)?
            .assume_checked()
            .script_pubkey();
        let txid = wallet::send(w, to, Amount::from_sat(1_000_000), |tx| {
            Ok(env.bitcoind.client.send_raw_transaction(tx)?)
        })?;
        Ok(format!(
            "regtest: the wallet sent 0.01 BTC to the node, broadcast through bitcoind: {txid}"
        ))
    })
}

/// A restore of the Haystack wallet from its descriptor, with or without the ledger file.
fn restore(app: &App, keep_ledger: bool, padding: Option<u32>) -> anyhow::Result<()> {
    // Checked before anything is deleted, so a refused restore leaves the wallet as it was.
    let padding = match (keep_ledger, padding) {
        (true, _) => None,
        (false, None) => bail!("restoring without the ledger needs a dial setting"),
        (false, Some(p)) if !PADDINGS.contains(&p) => {
            bail!("padding must be one of {PADDINGS:?}")
        }
        (false, Some(p)) => Some(p),
    };
    if app.action.lock().unwrap()["running"] == true {
        bail!("a regtest action is still running; try again in a moment");
    }
    let mut p = app.profiles[HAYSTACK]
        .try_lock()
        .map_err(|_| anyhow!("a sync is running; try again in a moment"))?;
    p.open = None;
    for path in [&p.files.db, &p.files.cache] {
        let _ = std::fs::remove_file(path);
    }
    let message = match padding {
        None => "restore: the wallet database and cache were deleted; the descriptor and the ledger file are kept, so the next sync sends exactly the old query".to_string(),
        Some(padding) => {
            let _ = std::fs::remove_file(&p.files.ledger);
            p.padding = padding;
            p.chain_share = 0.0;
            format!(
                "restore without the ledger, at padding {padding}: the old decoy counts and every chain decoy are gone, so any position whose count differs, and every chain decoy, changes on the wire"
            )
        }
    };
    p.view["padding"] = json!(p.padding);
    p.view["chain_share"] = json!(p.chain_share);
    // A restored wallet knows nothing until it syncs, so none of the old numbers stay up.
    for key in ["balance", "txs", "utxos", "last", "score", "last_error", "syncing"] {
        p.view[key] = Value::Null;
    }
    p.view["scoring"] = json!(false);
    p.view["ledger"] = json!(std::fs::read_to_string(&p.files.ledger).unwrap_or_default());
    app.publish(HAYSTACK, &p.view);
    app.say(&message);
    *app.action.lock().unwrap() =
        json!({ "what": "restore", "running": false, "ok": true, "message": message, "at": now_unix() });
    Ok(())
}

fn set_dial(app: &App, padding: u32, chain_share: f64) -> anyhow::Result<()> {
    if !PADDINGS.contains(&padding) {
        bail!("padding must be one of {PADDINGS:?}");
    }
    if !CHAIN_SHARES.iter().any(|s| (s - chain_share).abs() < 1e-9) {
        bail!("chain share must be one of {CHAIN_SHARES:?}");
    }
    if chain_share > 0.0 && !app.regtest {
        bail!("chain decoys are only offered on regtest in this demo");
    }
    let mut p = app.profiles[HAYSTACK]
        .try_lock()
        .map_err(|_| anyhow!("a sync is running; try again in a moment"))?;
    p.padding = padding;
    p.chain_share = chain_share;
    p.view["padding"] = json!(padding);
    p.view["chain_share"] = json!(chain_share);
    app.publish(HAYSTACK, &p.view);
    app.say(format!(
        "dial set to padding {padding}, chain share {:.0}%: positions already queried keep their decoys; only new positions get the new setting",
        chain_share * 100.0
    ));
    Ok(())
}

fn state(app: &App) -> Value {
    let world = app.world.lock().unwrap().clone();
    let next = app
        .next_auto
        .lock()
        .unwrap()
        .map(|due| due.saturating_duration_since(Instant::now()).as_secs_f64());
    json!({
        "status": *app.status.lock().unwrap(),
        "ready": world.is_some(),
        "regtest": app.regtest,
        "server": world.as_ref().map(|w| w.endpoint.url()),
        "local": world.as_ref().map(|w| w.endpoint.is_local()),
        "descriptors": world.as_ref().map(|w| w.public.clone()),
        "mean_minutes": app.mean.as_secs_f64() / 60.0,
        "default_mean_minutes": DEFAULT_MEAN.as_secs_f64() / 60.0,
        "next_auto_secs": next,
        "paddings": PADDINGS,
        "chain_shares": if app.regtest { CHAIN_SHARES.to_vec() } else { vec![0.0] },
        "profiles": *app.views.lock().unwrap(),
        "action": *app.action.lock().unwrap(),
        "log": app.log.lock().unwrap().iter().cloned().collect::<Vec<_>>(),
    })
}

fn respond(req: tiny_http::Request, code: u16, body: String, kind: &str) {
    let header = Header::from_bytes("Content-Type", kind).expect("valid header");
    let _ = req.respond(
        Response::from_string(body)
            .with_status_code(code)
            .with_header(header),
    );
}

/// Runs an action off the request thread, reporting a failure in the log.
fn spawn(
    app: &Arc<App>,
    what: &'static str,
    f: impl FnOnce(&App) -> anyhow::Result<()> + Send + 'static,
) {
    let app = app.clone();
    std::thread::spawn(move || {
        if let Err(e) = f(&app) {
            app.say(format!("{what}: {e}"));
        }
    });
}

/// A regtest action run off the request thread, with its progress and result kept in `app.action`
/// for the page. One at a time: a second press while one runs is refused straight away.
fn spawn_action(
    app: &Arc<App>,
    what: &'static str,
    doing: &'static str,
    f: impl FnOnce(&App) -> anyhow::Result<String> + Send + 'static,
) -> anyhow::Result<()> {
    {
        let mut action = app.action.lock().unwrap();
        if action["running"] == true {
            bail!("still busy: {}", action["message"].as_str().unwrap_or("another action"));
        }
        *action = json!({ "what": what, "running": true, "message": doing, "at": now_unix() });
    }
    let app = app.clone();
    std::thread::spawn(move || {
        let (ok, message) = match f(&app) {
            Ok(message) => (true, message),
            Err(e) => (false, format!("{what} failed: {e}")),
        };
        app.say(&message);
        *app.action.lock().unwrap() =
            json!({ "what": what, "running": false, "ok": ok, "message": message, "at": now_unix() });
    });
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let a = args()?;
    let mode_dir = a.data.join(if a.regtest {
        "regtest".to_string()
    } else {
        a.url.clone().unwrap_or_default().replace(['/', ':'], "_")
    });
    if a.regtest {
        // A fresh chain each run: files from an old chain would describe blocks that don't exist.
        let _ = std::fs::remove_dir_all(&mode_dir);
    }
    let mut profiles = Vec::new();
    for (which, name) in [(PLAIN, "plain"), (HAYSTACK, "haystack")] {
        let dir = mode_dir.join(name);
        std::fs::create_dir_all(&dir)?;
        let padding = if which == PLAIN { 1 } else { a.padding };
        profiles.push(Mutex::new(Profile {
            files: Files::in_dir(&dir),
            padding,
            chain_share: 0.0,
            open: None,
            view: json!({ "name": name, "padding": padding, "chain_share": 0.0, "history": [] }),
        }));
    }
    let views = [
        profiles[0].lock().unwrap().view.clone(),
        profiles[1].lock().unwrap().view.clone(),
    ];
    let mut it = profiles.into_iter();
    let app = Arc::new(App {
        regtest: a.regtest,
        status: Mutex::new("starting".into()),
        world: Mutex::new(None),
        env: Mutex::new(None),
        profiles: [it.next().expect("two"), it.next().expect("two")],
        views: Mutex::new(views),
        log: Mutex::new(VecDeque::new()),
        action: Mutex::new(Value::Null),
        pins: PinFile::new(a.data.join("pins.json")),
        train: a.train.clone(),
        mean: a.mean,
        next_auto: Mutex::new(None),
    });

    {
        let app = app.clone();
        let url = a.url.clone();
        std::thread::spawn(move || {
            let world = match url {
                None => build_regtest(&app),
                Some(url) => (|| {
                    let (descriptors, account) = capture_wallet()?;
                    Ok(World {
                        endpoint: Endpoint::parse(&url)?,
                        public: public_descriptors(&descriptors)?,
                        descriptors,
                        key: DecoyKey::from_xpubs([account]).expect("one xpub"),
                    })
                })(),
            };
            match world {
                Ok(w) => {
                    app.say(format!("ready: syncing against {}", w.endpoint.url()));
                    *app.status.lock().unwrap() = "ready".into();
                    *app.world.lock().unwrap() = Some(w);
                }
                Err(e) => {
                    app.say(format!("startup failed: {e}"));
                    *app.status.lock().unwrap() = format!("startup failed: {e}");
                }
            }
        });
    }
    {
        let app = app.clone();
        std::thread::spawn(move || auto_loop(app));
    }
    {
        let app = app.clone();
        ctrlc::set_handler(move || {
            eprintln!("haystack-demo: stopping");
            // Dropping the test environment stops bitcoind and electrs.
            drop(app.env.lock().unwrap_or_else(|e| e.into_inner()).take());
            std::process::exit(0);
        })?;
    }

    // 127.0.0.1 unless told otherwise: the Docker image passes 0.0.0.0, because a container's own
    // loopback can't be reached from the host, and publishes the port on the host's loopback only.
    let server = Server::http((a.host.as_str(), a.port)).map_err(|e| anyhow!("{e}"))?;
    eprintln!(
        "haystack-demo: open http://127.0.0.1:{}  (automatic sync mean {:.1} minutes)",
        a.port,
        a.mean.as_secs_f64() / 60.0
    );
    for mut req in server.incoming_requests() {
        let mut body = String::new();
        let _ = req.as_reader().read_to_string(&mut body);
        let input: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let method = req.method().clone();
        let url = req.url().to_string();
        match (method, url.as_str()) {
            (Method::Get, "/") => respond(req, 200, PAGE.to_string(), "text/html; charset=utf-8"),
            (Method::Get, "/api/state") => {
                respond(req, 200, state(&app).to_string(), "application/json")
            }
            // Actions need a custom header, which a browser sends cross-site only after a CORS
            // preflight this server never approves, so another web page can't drive the wallet.
            (Method::Post, _)
                if !req
                    .headers()
                    .iter()
                    .any(|h| h.field.equiv("X-Haystack-Demo")) =>
            {
                respond(
                    req,
                    403,
                    "missing X-Haystack-Demo header".into(),
                    "text/plain",
                )
            }
            (Method::Post, path) => {
                let reply = match path {
                    "/api/sync" => {
                        let which = if input["profile"] == "plain" {
                            PLAIN
                        } else {
                            HAYSTACK
                        };
                        // Refused here, not only in the log, while the published view says it's busy.
                        let view = app.views.lock().unwrap()[which].clone();
                        if !view["syncing"].is_null() || view["scoring"] == true {
                            Err(anyhow!("a sync of this wallet is already running"))
                        } else {
                            spawn(&app, "manual sync", move |app| sync(app, which, "manual"));
                            Ok(())
                        }
                    }
                    "/api/dial" => set_dial(
                        &app,
                        input["padding"].as_u64().unwrap_or(0) as u32,
                        input["chain_share"].as_f64().unwrap_or(0.0),
                    ),
                    "/api/pay" => {
                        spawn_action(&app, "pay", "someone is paying the wallet 0.004 BTC…", pay)
                    }
                    "/api/mine" => spawn_action(&app, "mine", "mining a block…", |app| {
                        with_env(app, |env| mine(env, 1).map_err(|e| anyhow!("{e}")))?;
                        Ok("regtest: mined one block".into())
                    }),
                    "/api/send" => {
                        spawn_action(&app, "send", "the wallet is sending 0.01 BTC…", send)
                    }
                    "/api/restore" => restore(
                        &app,
                        input["keep_ledger"].as_bool().unwrap_or(true),
                        input["padding"].as_u64().map(|p| p as u32),
                    ),
                    _ => Err(anyhow!("no such action")),
                };
                match reply {
                    Ok(()) => respond(
                        req,
                        200,
                        json!({ "ok": true }).to_string(),
                        "application/json",
                    ),
                    Err(e) => respond(
                        req,
                        400,
                        json!({ "ok": false, "error": e.to_string() }).to_string(),
                        "application/json",
                    ),
                }
            }
            _ => respond(req, 404, "not found".into(), "text/plain"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `capture/` derives the same public-seed wallet in its own code, and the committed fixtures
    /// were scanned with it. If the two ever drift, the demo's honeypot runs stop matching them.
    #[test]
    fn demo_wallet_is_the_one_capture_scans() {
        let path = score::repo_root().join("tests/fixtures/bdk-capture-truth.json");
        let fixture: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let (d, _) = capture_wallet().unwrap();
        for (ours, key) in [(&d.external, "external_descriptor"), (&d.internal, "internal_descriptor")] {
            let theirs = fixture[key].as_str().unwrap();
            // The fixture's descriptors carry a `#checksum` suffix; ours are bare.
            assert_eq!(theirs.split('#').next().unwrap(), ours, "{key}");
        }
    }
}
