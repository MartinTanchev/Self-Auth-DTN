//! A self-auth-dtn application endpoint on a uD3TN node, over AAP 2.0.
//!
//! uD3TN forwards the bundles; this program secures their payloads (self-auth
//! block, BIB, optional BCB, all inside the payload) and checks them on
//! arrival, with bulletins carried the same way.
//!
//!   ud3tn_node listen --socket ud3tn-b.aap2.socket --name b [--count N]
//!   ud3tn_node send   --socket ud3tn-a.aap2.socket --name a \
//!                     --to dtn://b.dtn/sad --to-name b \
//!                     [--msg TEXT] [--count N] [--confidential] \
//!                     [--bulletins first|last|none]
//!   ud3tn_node revoke --socket ud3tn-a.aap2.socket --name a --to dtn://b.dtn/sad \
//!                     [--effective-at UNIX_SECONDS]
//!
//! Common: --agent ID (default "sad"), --secret S (default "self-auth-dtn"),
//! --tcp HOST:PORT instead of --socket.
//!
//! LAB PROVISIONING, NOT A DEPLOYMENT: every key (node identities, KEM keys,
//! the "lab" collective root) is derived from public labels, so any process
//! can mint any node's bulletins. It exists so two terminals can exercise
//! the protocol through a real bundle agent without a provisioning step.
//!
//! Built with `--features ud3tn` (mock crypto) or `--features "ud3tn pq"`
//! (ML-DSA-65 / ML-KEM-1024). Both ends must use the same build.

use self_auth_dtn::prelude::*;
use self_auth_dtn::sha256::sha256;
use self_auth_dtn::ud3tn::Aap2Client;
use self_auth_dtn::verify::Sender;
use std::io::{Read, Write};
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "pq")]
type Sig = MlDsa65;
#[cfg(feature = "pq")]
type Kem = MlKem1024;
#[cfg(feature = "pq")]
const SUITE: u64 = SUITE_ML_DSA_65_SHA256;

#[cfg(not(feature = "pq"))]
type Sig = MockSig;
#[cfg(not(feature = "pq"))]
type Kem = MockKem;
#[cfg(not(feature = "pq"))]
const SUITE: u64 = SUITE_MOCK;

const COLLECTIVE: &str = "lab";

// ---------------------------------------------------------------------------
// Lab provisioning: keys from public labels (see the module docs)
// ---------------------------------------------------------------------------

fn lab_seed(kind: &str, name: &str) -> [u8; 32] {
    sha256(format!("self-auth-dtn lab:{kind}:{name}").as_bytes())
}

fn lab_identity(name: &str) -> Identity<Sig> {
    Identity::incept(
        &lab_seed("sig0", name),
        &lab_seed("sig1", name),
        name.as_bytes(),
    )
}

fn lab_kem(name: &str) -> (Vec<u8>, <Kem as KemScheme>::DecapKey) {
    Kem::keygen(&lab_seed("kem", name))
}

/// A fresh authority per bulletin, so every membership carries seq 1 and a
/// revocation (seq 2) supersedes it, whichever process minted either.
fn lab_authority() -> Authority<Sig> {
    Authority::new(COLLECTIVE, &lab_seed("root", COLLECTIVE))
}

fn lab_membership(name: &str) -> Bulletin {
    let id = lab_identity(name).node_id();
    lab_authority().announce_member(&id, None, &lab_kem(name).0)
}

fn lab_revocation(name: &str, effective_at: u64) -> Bulletin {
    let id = lab_identity(name).node_id();
    let mut a = lab_authority();
    let _ = a.announce_member(&id, None, &lab_kem(name).0); // seq 1
    a.revoke_effective(&id, RevocationReason::KeyCompromise, effective_at) // seq 2
}

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

struct Args {
    cmd: String,
    socket: Option<String>,
    tcp: Option<String>,
    name: String,
    agent: String,
    secret: String,
    to: String,
    to_name: String,
    msg: String,
    count: Option<u64>,
    confidential: bool,
    bulletins: String,
    effective_at: Option<u64>,
}

fn usage() -> ! {
    eprintln!(
        "usage: ud3tn_node listen|send|revoke --socket PATH|--tcp HOST:PORT --name NODE \
         [--agent ID] [--secret S] [--to EID --to-name NODE] [--msg TEXT] [--count N] \
         [--confidential] [--bulletins first|last|none] [--effective-at T]"
    );
    exit(2)
}

fn parse() -> Args {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_else(|| usage());
    let mut a = Args {
        cmd,
        socket: None,
        tcp: None,
        name: String::new(),
        agent: "sad".into(),
        secret: "self-auth-dtn".into(),
        to: String::new(),
        to_name: String::new(),
        msg: "hello from self-auth-dtn".into(),
        count: None,
        confidential: false,
        bulletins: "first".into(),
        effective_at: None,
    };
    while let Some(flag) = it.next() {
        let mut val = || it.next().unwrap_or_else(|| usage());
        match flag.as_str() {
            "--socket" => a.socket = Some(val()),
            "--tcp" => a.tcp = Some(val()),
            "--name" => a.name = val(),
            "--agent" => a.agent = val(),
            "--secret" => a.secret = val(),
            "--to" => a.to = val(),
            "--to-name" => a.to_name = val(),
            "--msg" => a.msg = val(),
            "--count" => a.count = Some(val().parse().unwrap_or_else(|_| usage())),
            "--bulletins" => a.bulletins = val(),
            "--effective-at" => a.effective_at = Some(val().parse().unwrap_or_else(|_| usage())),
            "--confidential" => a.confidential = true,
            _ => usage(),
        }
    }
    if a.name.is_empty() || (a.socket.is_none() && a.tcp.is_none()) {
        usage();
    }
    a
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn short(id: &NodeId) -> String {
    node_id_hex(id)[..12].to_string()
}

/// Connect and register, as sender or subscriber.
fn open(a: &Args, subscriber: bool) -> Box<dyn Endpoint> {
    fn go<S: Read + Write + 'static>(
        c: Result<Aap2Client<S>, self_auth_dtn::ud3tn::Aap2Error>,
        a: &Args,
        subscriber: bool,
    ) -> Box<dyn Endpoint> {
        let mut c = c.unwrap_or_else(|e| {
            eprintln!("connect: {e}");
            exit(1)
        });
        let eid = c.endpoint_for(&a.agent);
        c.configure(&eid, subscriber, &a.secret)
            .unwrap_or_else(|e| {
                eprintln!("register {eid}: {e}");
                exit(1)
            });
        let role = if subscriber { "receiving" } else { "sending" };
        println!("node {} registered {eid} ({role})", c.node_id());
        Box::new(c)
    }
    if let Some(addr) = &a.tcp {
        return go(Aap2Client::connect_tcp(addr.as_str()), a, subscriber);
    }
    #[cfg(unix)]
    {
        go(
            Aap2Client::connect_unix(a.socket.as_deref().unwrap()),
            a,
            subscriber,
        )
    }
    #[cfg(not(unix))]
    {
        eprintln!("--socket needs a Unix platform; use --tcp");
        exit(2)
    }
}

/// Object-safe view of a configured client.
trait Endpoint {
    fn send(&mut self, dst: &str, payload: &[u8]);
    fn receive(&mut self) -> (String, Vec<u8>);
}

impl<S: Read + Write> Endpoint for Aap2Client<S> {
    fn send(&mut self, dst: &str, payload: &[u8]) {
        Aap2Client::send(self, dst, payload).unwrap_or_else(|e| {
            eprintln!("send to {dst}: {e}");
            exit(1)
        })
    }
    fn receive(&mut self) -> (String, Vec<u8>) {
        let (meta, payload) = Aap2Client::receive(self).unwrap_or_else(|e| {
            eprintln!("receive: {e}");
            exit(1)
        });
        (meta.src_eid, payload)
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_send(a: &Args) {
    if a.to.is_empty() || (a.confidential && a.to_name.is_empty()) {
        usage();
    }
    let id = lab_identity(&a.name);
    println!("sender {} = {}", a.name, short(&id.node_id()));
    let mut ep = open(a, false);

    let ship_bulletin = |ep: &mut Box<dyn Endpoint>| {
        let b = lab_membership(&a.name);
        ep.send(&a.to, &encode_bulletin(&b));
        println!("sent membership bulletin for {} to {}", a.name, a.to);
    };
    if a.bulletins == "first" {
        ship_bulletin(&mut ep);
    }

    // The sender learns the destination's KEM key the normal way: from a
    // membership bulletin (here minted locally, lab provisioning).
    let mut trust = TrustStore::new(COLLECTIVE, lab_authority().root_public_key());
    let dest_id = if a.confidential {
        let b = lab_membership(&a.to_name);
        trust.apply::<Sig>(&b).expect("lab bulletin");
        Some(lab_identity(&a.to_name).node_id())
    } else {
        None
    };

    let sender = Sender::new(&id, SourceName::SelfCertifying);
    let n = a.count.unwrap_or(1);
    for i in 0..n {
        let text = if n == 1 {
            a.msg.clone()
        } else {
            format!("{} #{}", a.msg, i + 1)
        };
        let bundle = match &dest_id {
            None => sender.send_plain(text.as_bytes()),
            Some(dest) => {
                // Fresh per bundle: encapsulation seed and nonce.
                let salt = format!("{}:{}:{}", a.name, now_nanos(), i);
                let kem_seed = sha256(format!("kem-seed:{salt}").as_bytes());
                let nonce_full = sha256(format!("nonce:{salt}").as_bytes());
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&nonce_full[..12]);
                sender
                    .send_confidential::<Kem>(&trust, dest, text.as_bytes(), &kem_seed, nonce)
                    .unwrap_or_else(|e| {
                        eprintln!("seal: {e:?}");
                        exit(1)
                    })
            }
        };
        let adu = encode_bundle(&bundle, SUITE);
        ep.send(&a.to, &adu);
        let kind = if dest_id.is_some() {
            "confidential"
        } else {
            "plain"
        };
        println!("sent {kind} bundle {} ({} B payload ADU)", i + 1, adu.len());
    }

    if a.bulletins == "last" {
        ship_bulletin(&mut ep);
    }
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn cmd_revoke(a: &Args) {
    if a.to.is_empty() {
        usage();
    }
    let effective_at = a.effective_at.unwrap_or(0);
    let mut ep = open(a, false);
    ep.send(
        &a.to,
        &encode_bulletin(&lab_revocation(&a.name, effective_at)),
    );
    println!(
        "sent revocation of {} (effective_at {effective_at}) to {}",
        a.name, a.to
    );
}

#[derive(Default)]
struct Tally {
    bulletins: u64,
    bundles: u64,
    authorized: u64,
    held: u64,
    decrypted: u64,
    refused: u64,
}

fn cmd_listen(a: &Args) {
    let me = lab_identity(&a.name);
    println!("receiver {} = {}", a.name, short(&me.node_id()));
    let (_, decap) = lab_kem(&a.name);
    let mut rx = Receiver::<Kem>::new(
        TrustStore::new(COLLECTIVE, lab_authority().root_public_key()),
        decap,
    );
    let mut ep = open(a, true);
    let mut t = Tally::default();
    let mut seen = 0u64;
    loop {
        if a.count.is_some_and(|n| seen >= n) {
            break;
        }
        let (src, payload) = ep.receive();
        seen += 1;
        let at = now();
        match adu_kind(&payload) {
            Some(ADU_BULLETIN) => {
                t.bulletins += 1;
                match decode_bulletin(&payload) {
                    Err(e) => {
                        t.refused += 1;
                        println!("[{src}] bulletin malformed: {e:?}");
                    }
                    Ok(b) => match rx.apply_bulletin_at::<Sig>(&b, at) {
                        Ok(Applied::Member(id)) => println!(
                            "[{src}] bulletin: {} is a member of {}; {} held bundle(s) promotable",
                            short(&id),
                            b.issuer,
                            rx.promotable_history(&id).len()
                        ),
                        Ok(Applied::Revoked(id)) => println!(
                            "[{src}] bulletin: {} revoked; {} held bundle(s) still promotable",
                            short(&id),
                            rx.promotable_history(&id).len()
                        ),
                        Ok(other) => println!("[{src}] bulletin: {other:?}"),
                        Err(TrustError::StaleSequence { seen, got }) if seen == got => {
                            println!("[{src}] bulletin: duplicate of one already applied")
                        }
                        Err(e) => println!("[{src}] bulletin refused: {e:?}"),
                    },
                }
            }
            Some(ADU_BUNDLE) => {
                t.bundles += 1;
                let bundle = match decode_bundle(&payload) {
                    Ok((suite, _)) if suite != SUITE => {
                        t.refused += 1;
                        println!("[{src}] bundle refused: suite {suite}, this build is {SUITE}");
                        continue;
                    }
                    Ok((_, b)) => b,
                    Err(e) => {
                        t.refused += 1;
                        println!("[{src}] bundle malformed: {e:?}");
                        continue;
                    }
                };
                match rx.accept_at::<Sig>(&bundle, at) {
                    Err(e) => {
                        t.refused += 1;
                        println!("[{src}] bundle refused: {e:?}");
                    }
                    Ok(v) => {
                        let body = match &v.payload {
                            ReceivedPayload::Plain(p) => {
                                format!("plain {:?}", String::from_utf8_lossy(p))
                            }
                            ReceivedPayload::Decrypted(p) => {
                                t.decrypted += 1;
                                format!("decrypted {:?}", String::from_utf8_lossy(p))
                            }
                            ReceivedPayload::Undecryptable => "undecryptable".into(),
                        };
                        let auth = match &v.authorization {
                            Ok(_) => {
                                t.authorized += 1;
                                "authorized".to_string()
                            }
                            Err(e) => {
                                t.held += 1;
                                format!("held ({e:?})")
                            }
                        };
                        println!(
                            "[{src}] bundle from {}: binding ok, {auth}, {body}, {} accumulated",
                            short(&v.node_id),
                            v.accumulated
                        );
                    }
                }
            }
            _ => {
                t.refused += 1;
                println!("[{src}] not a self-auth-dtn ADU ({} B)", payload.len());
            }
        }
        std::io::stdout().flush().ok();
    }
    println!(
        "summary: bulletins={} bundles={} authorized={} held={} decrypted={} refused={}",
        t.bulletins, t.bundles, t.authorized, t.held, t.decrypted, t.refused
    );
}

fn main() {
    let a = parse();
    match a.cmd.as_str() {
        "listen" => cmd_listen(&a),
        "send" => cmd_send(&a),
        "revoke" => cmd_revoke(&a),
        _ => usage(),
    }
}
