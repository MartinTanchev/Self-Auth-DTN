//! The `contactplan` measurement on the CCSDS DTN Reference Scenarios.
//!
//! `contactplan` scores receiver policies on a synthetic, periodic eight-node
//! plan with one small bundle per asset every few hours. This example uses
//! the CCSDS lunar and Mars reference scenarios instead
//! (esa/ccsds-dtn-reference-scenarios, vendored under `scenarios/ccsds`):
//! contacts from flight-dynamics software with the scenario's link error
//! model applied, real link rates, and the scenario's own traffic flows.
//!
//! Real rates and volumes change the question. A rover producing 230 MB/h of
//! science cannot simply re-offer what was refused; whatever it cannot hand
//! over piles up and has to drain through later passes. So links are served
//! as capacity-limited FIFO queues, one transmitter per source (the fastest
//! usable link at each instant), and four policies are scored:
//!
//!   blind                  any foreign next hop accepts at once (insecure floor)
//!   bulletin-only          a next hop accepts only once it can authorize the
//!                          source; the source uses no other hop (oracle: it
//!                          knows exactly when, so no capacity is wasted)
//!   self-auth, any hop     the source hands data to any foreign next hop, as
//!                          on the slides; the hop verifies binding, holds, and
//!                          releases when it can authorize
//!   self-auth, agreed hop  as above, but the source only uses a hop once its
//!                          own trust store lists that hop's collective as a
//!                          peer, i.e. once the sender itself knows of the
//!                          agreement
//!
//! Delivery is measured at the boundary, as in `contactplan`: acceptance by
//! the first node of another collective. Only flows whose source has no
//! next hop inside its own collective are scored (user missions and their
//! control centres); provider-internal flows are listed as excluded.
//!
//! Two cases per scenario:
//!
//!   federation     every mission <-> infrastructure agreement lands on
//!                  `--peer-day` (slides: federation after deployment)
//!   cross-support  missions are pre-peered with every infrastructure
//!                  collective except one provider (`--late`, orange by
//!                  default), whose cross-support is agreed late (LunaNet
//!                  multi-provider case). Which provider is late decides the
//!                  outcome: run both.
//!
//! Bulletins flood over the same contacts as data: earliest arrival over the
//! time-varying graph, link delay included, bulletin size ignored. Each
//! node's trust state is the crate's real `TrustStore`, fed bulletins in
//! arrival order. On the any-hop path, every block is a real bundle accepted
//! by a real `Receiver`, and the held history is checked for promotion at
//! the end.
//!
//! Traffic is sampled into blocks: one block per flow every
//! max(interval, --sample-min), carrying everything the flow generates in
//! that span (signature included). Latency is per block, from the start of
//! its span.
//!
//! Not modelled: relay storage limits, the relay-to-ground leg, receive-side
//! contention, the first-contact identity overhead (8.6 kB once per pair).
//!
//! Run with:  cargo run --release --example refscenario
//!            cargo run --release --example refscenario -- lunar --case federation
//!            cargo run --release --example refscenario -- mars --peer-day 5 --contacts planned
//!
//! Options:   [lunar|mars|all]  --case federation|cross-support|all
//!            --peer-day D (10)  --contacts actual|planned (actual)
//!            --sample-min M (60)  --late orange|blue (orange)  --dir PATH

use self_auth_dtn::prelude::*;
use self_auth_dtn::verify::MAX_HISTORY_PER_SOURCE;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::path::{Path, PathBuf};

type Sig = MockSig;
type Kem = MockKem;

const HOUR: f64 = 3600.0;
const DAY: f64 = 24.0 * HOUR;

// Per-bundle signature, ML-DSA-65 figure from `overhead`.
const STEADY_OVERHEAD_B: f64 = 3309.0;

const VERSION: &str = "v1.0.1";

fn seed_bytes(i: usize, tag: u8) -> [u8; 32] {
    let mut s = [tag; 32];
    s[0] = i as u8;
    s[1] = (i >> 8) as u8;
    s
}

// ---------------------------------------------------------------------------
// Minimal JSON reader (the scenario files are flat arrays of flat objects;
// this keeps the crate at one dependency).
// ---------------------------------------------------------------------------

#[allow(dead_code)] // Bool and Null are parsed but unused
#[derive(Debug, Clone)]
enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, k: &str) -> Option<&Json> {
        match self {
            Json::Obj(v) => v.iter().find(|(kk, _)| kk == k).map(|(_, v)| v),
            _ => None,
        }
    }
    fn str(&self, k: &str) -> Option<&str> {
        match self.get(k) {
            Some(Json::Str(s)) => Some(s),
            _ => None,
        }
    }
    fn num(&self, k: &str) -> Option<f64> {
        match self.get(k) {
            Some(Json::Num(n)) => Some(*n),
            _ => None,
        }
    }
}

struct JsonParser<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> JsonParser<'a> {
    fn peek(&mut self) -> Option<u8> {
        while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
        self.s.get(self.i).copied()
    }

    fn eat(&mut self, c: u8) -> Result<(), String> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected '{}' at byte {}", c as char, self.i))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        match self.peek() {
            Some(b'{') => {
                self.i += 1;
                let mut v = Vec::new();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Ok(Json::Obj(v));
                }
                loop {
                    let k = self.string()?;
                    self.eat(b':')?;
                    v.push((k, self.value()?));
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Json::Obj(v));
                        }
                        _ => return Err(format!("bad object at byte {}", self.i)),
                    }
                }
            }
            Some(b'[') => {
                self.i += 1;
                let mut v = Vec::new();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(Json::Arr(v));
                }
                loop {
                    v.push(self.value()?);
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Json::Arr(v));
                        }
                        _ => return Err(format!("bad array at byte {}", self.i)),
                    }
                }
            }
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(_) => self.number(),
            None => Err("unexpected end of input".into()),
        }
    }

    fn literal(&mut self, word: &str, v: Json) -> Result<Json, String> {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(format!("bad literal at byte {}", self.i))
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        while self.i < self.s.len() && b"+-0123456789.eE".contains(&self.s[self.i]) {
            self.i += 1;
        }
        std::str::from_utf8(&self.s[start..self.i])
            .ok()
            .and_then(|t| t.parse::<f64>().ok())
            .map(Json::Num)
            .ok_or_else(|| format!("bad number at byte {}", start))
    }

    fn string(&mut self) -> Result<String, String> {
        self.eat(b'"')?;
        let mut out = Vec::new();
        while self.i < self.s.len() {
            let c = self.s[self.i];
            self.i += 1;
            match c {
                b'"' => return String::from_utf8(out).map_err(|e| e.to_string()),
                b'\\' => {
                    let e = *self.s.get(self.i).ok_or_else(|| "bad escape".to_string())?;
                    self.i += 1;
                    match e {
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'u' => {
                            let hex = self
                                .s
                                .get(self.i..self.i + 4)
                                .and_then(|h| std::str::from_utf8(h).ok())
                                .and_then(|h| u32::from_str_radix(h, 16).ok())
                                .ok_or_else(|| format!("bad \\u escape at byte {}", self.i))?;
                            self.i += 4;
                            let ch = char::from_u32(hex).unwrap_or('\u{fffd}');
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        other => out.push(other),
                    }
                }
                _ => out.push(c),
            }
        }
        Err("unterminated string".into())
    }
}

fn parse_json(text: &str) -> Result<Json, String> {
    let mut p = JsonParser {
        s: text.as_bytes(),
        i: 0,
    };
    let v = p.value()?;
    if p.peek().is_some() {
        return Err(format!("trailing data at byte {}", p.i));
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// Scenario definitions: which node belongs to which organisation. Taken from
// the scenario descriptions (Topology section), not from the data files.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    Mission,
    Infrastructure,
}

struct Org {
    name: &'static str,
    role: Role,
    members: &'static [&'static str],
    /// Ground nodes where the organisation's authority issues bulletins.
    issuers: &'static [&'static str],
}

struct Spec {
    key: &'static str,
    title: &'static str,
    dir: &'static str,
    orgs: &'static [Org],
    /// The provider whose cross-support is agreed late in `cross-support`.
    cross_support_late: &'static str,
}

/// Lunar Communication v1.0.1, "Topology": red base, green rover, yellow
/// Gateway user, orange provider (lrec1, lgs1, lre1), blue provider (lrec2,
/// lgs2, lgs3, lgw, lre2).
const LUNAR: Spec = Spec {
    key: "lunar",
    title: "CCSDS lunar communication",
    dir: "lunar-communication",
    orgs: &[
        Org {
            name: "base",
            role: Role::Mission,
            members: &["lbcc", "lb"],
            issuers: &["lbcc"],
        },
        Org {
            name: "rover",
            role: Role::Mission,
            members: &["lrcc", "lrov"],
            issuers: &["lrcc"],
        },
        Org {
            name: "gateway-user",
            role: Role::Mission,
            members: &["lucc", "lgwu"],
            issuers: &["lucc"],
        },
        Org {
            name: "provider-orange",
            role: Role::Infrastructure,
            members: &["lrec1", "lgs1", "lre1"],
            issuers: &["lrec1"],
        },
        Org {
            name: "provider-blue",
            role: Role::Infrastructure,
            members: &["lrec2", "lgs2", "lgs3", "lgw", "lre2"],
            issuers: &["lrec2"],
        },
    ],
    cross_support_late: "provider-orange",
};

/// Mars Communication v1.0.1, "Topology": red and green rovers with their
/// control centres, white relay coordination centre, orange provider (mrec1,
/// mgs1, mre1), blue provider (mrec2, mgs2, mre2, mre3).
const MARS: Spec = Spec {
    key: "mars",
    title: "CCSDS Mars communication",
    dir: "mars-communication",
    orgs: &[
        Org {
            name: "rover-1",
            role: Role::Mission,
            members: &["mr1c", "mr1"],
            issuers: &["mr1c"],
        },
        Org {
            name: "rover-2",
            role: Role::Mission,
            members: &["mr2c", "mr2"],
            issuers: &["mr2c"],
        },
        Org {
            name: "relay-coordination",
            role: Role::Infrastructure,
            members: &["mrecc"],
            issuers: &["mrecc"],
        },
        Org {
            name: "provider-orange",
            role: Role::Infrastructure,
            members: &["mrec1", "mgs1", "mre1"],
            issuers: &["mrec1"],
        },
        Org {
            name: "provider-blue",
            role: Role::Infrastructure,
            members: &["mrec2", "mgs2", "mre2", "mre3"],
            issuers: &["mrec2"],
        },
    ],
    cross_support_late: "provider-orange",
};

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

struct Node {
    label: String,
    ipn: u64,
    org: usize,
}

struct Contact {
    from: usize,
    to: usize,
    start: f64,
    end: f64,
    rate: f64,
    delay: f64,
}

struct Flow {
    info: String,
    src: usize,
    start: f64,
    end: f64,
    adu: f64,
    interval: f64,
    ttl: f64,
    ttl_filled: bool,
}

struct Scenario {
    nodes: Vec<Node>,
    contacts: Vec<Contact>,
    flows: Vec<Flow>,
    horizon: f64,
    notes: Vec<String>,
}

fn ipn_node(eid: &str) -> Result<u64, String> {
    eid.trim()
        .strip_prefix("ipn:")
        .and_then(|r| r.split('.').next())
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| format!("not an ipn EID: {}", eid))
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path.display(), e))
}

fn load(root: &Path, spec: &Spec, contacts_file: &str) -> Result<Scenario, String> {
    let dir = root.join(spec.dir).join(VERSION);
    let mut notes = Vec::new();

    // Nodes.
    let nodes_json = parse_json(&read(&dir.join("nodes.json"))?)?;
    let Json::Arr(items) = nodes_json else {
        return Err("nodes.json: expected an array".into());
    };
    let mut nodes = Vec::new();
    for it in &items {
        let label = it
            .str("node_label")
            .ok_or("nodes.json: node_label")?
            .trim()
            .to_string();
        let ipn = ipn_node(it.str("node_id").ok_or("nodes.json: node_id")?)?;
        let org = spec
            .orgs
            .iter()
            .position(|o| o.members.contains(&label.as_str()))
            .ok_or_else(|| {
                format!(
                    "node {} is not assigned to an organisation in the {} table",
                    label, spec.key
                )
            })?;
        nodes.push(Node { label, ipn, org });
    }
    for o in spec.orgs {
        for m in o.members.iter().chain(o.issuers.iter()) {
            if !nodes.iter().any(|n| n.label == *m) {
                return Err(format!(
                    "organisation table names {}, which nodes.json does not define",
                    m
                ));
            }
        }
    }
    let by_label: HashMap<String, usize> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.label.clone(), i))
        .collect();
    let by_ipn: HashMap<u64, usize> = nodes.iter().enumerate().map(|(i, n)| (n.ipn, i)).collect();

    // Contacts. Header row, then source,destination,start,end,rate,delay,type.
    let mut raw = Vec::new();
    for (ln, line) in read(&dir.join(contacts_file))?.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("source") {
            continue;
        }
        let f: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if f.len() < 7 {
            return Err(format!("{}:{}: expected 7 fields", contacts_file, ln + 1));
        }
        let idx = |l: &str| {
            by_label
                .get(l)
                .copied()
                .ok_or_else(|| format!("{}:{}: unknown node {}", contacts_file, ln + 1, l))
        };
        let num = |s: &str| {
            s.parse::<f64>()
                .map_err(|_| format!("{}:{}: bad number {}", contacts_file, ln + 1, s))
        };
        raw.push((
            idx(f[0])?,
            idx(f[1])?,
            num(f[2])?,
            num(f[3])?,
            num(f[4])?,
            num(f[5])?,
        ));
    }
    let horizon = raw
        .iter()
        .filter(|r| r.3 >= 0.0)
        .map(|r| r.3)
        .fold(0.0, f64::max);
    if horizon <= 0.0 {
        return Err("no finite contact end; cannot infer the simulation horizon".into());
    }
    let contacts: Vec<Contact> = raw
        .into_iter()
        .map(|(from, to, start, end, rate, delay)| Contact {
            from,
            to,
            start,
            end: if end < 0.0 { horizon } else { end },
            rate,
            delay,
        })
        .collect();

    // Traffic.
    let traffic = parse_json(&read(&dir.join("traffic.json"))?)?;
    let Json::Arr(items) = traffic else {
        return Err("traffic.json: expected an array".into());
    };
    let known_ttls: Vec<f64> = items.iter().filter_map(|it| it.num("ttl")).collect();
    let default_ttl = known_ttls.iter().cloned().fold(0.0, f64::max);
    let mut flows = Vec::new();
    for it in &items {
        let info = it.str("info").unwrap_or("").trim().to_string();
        let src_ipn = ipn_node(it.str("src").ok_or("traffic.json: src")?)?;
        let src = *by_ipn
            .get(&src_ipn)
            .ok_or_else(|| format!("traffic.json: unknown source ipn:{}", src_ipn))?;
        let num = |k: &str| {
            it.num(k)
                .ok_or_else(|| format!("traffic.json: {} missing in '{}'", k, info))
        };
        let end = num("end_time")?;
        let (ttl, ttl_filled) = match it.num("ttl") {
            Some(t) => (t, false),
            None => {
                notes.push(format!(
                    "traffic.json entry '{}' has no ttl; using {} d, as every other flow",
                    info,
                    default_ttl / DAY
                ));
                (default_ttl, true)
            }
        };
        let (start, adu, interval) = (num("start_time")?, num("adu_size")?, num("interval")?);
        if interval <= 0.0 || ttl <= 0.0 {
            return Err(format!(
                "traffic.json: non-positive interval or ttl in '{}'",
                info
            ));
        }
        flows.push(Flow {
            info,
            src,
            start,
            end: if end < 0.0 { horizon } else { end },
            adu,
            interval,
            ttl,
            ttl_filled,
        });
    }
    Ok(Scenario {
        nodes,
        contacts,
        flows,
        horizon,
        notes,
    })
}

// ---------------------------------------------------------------------------
// Bulletin flooding: earliest arrival over the time-varying contact graph.
// ---------------------------------------------------------------------------

fn flood(sc: &Scenario, out: &[Vec<usize>], sources: &[(usize, f64)]) -> Vec<f64> {
    let key = |t: f64| (t * 1000.0).round() as u64;
    let mut arr = vec![f64::INFINITY; sc.nodes.len()];
    let mut heap = BinaryHeap::new();
    for &(v, t) in sources {
        if t < arr[v] {
            arr[v] = t;
            heap.push(Reverse((key(t), v)));
        }
    }
    while let Some(Reverse((_, u))) = heap.pop() {
        let t = arr[u];
        for &ci in &out[u] {
            let c = &sc.contacts[ci];
            if t >= c.end {
                continue;
            }
            let a = t.max(c.start) + c.delay;
            if a < arr[c.to] && a < sc.horizon {
                arr[c.to] = a;
                heap.push(Reverse((key(a), c.to)));
            }
        }
    }
    arr
}

fn apply_pending(rx: &mut Receiver<Kem>, pending: &mut Vec<usize>, bulletins: &[Bulletin]) {
    loop {
        pending.sort_by(|&x, &y| {
            (bulletins[x].issuer.as_str(), bulletins[x].seq)
                .cmp(&(bulletins[y].issuer.as_str(), bulletins[y].seq))
        });
        let mut progress = false;
        pending.retain(|&bi| {
            if rx.apply_bulletin::<Sig>(&bulletins[bi]).is_ok() {
                progress = true;
                false
            } else {
                true
            }
        });
        if !progress {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Policy {
    Blind,
    BulletinOnly,
    SelfAuthAny,
    SelfAuthAgreed,
}

const POLICIES: [Policy; 4] = [
    Policy::Blind,
    Policy::BulletinOnly,
    Policy::SelfAuthAny,
    Policy::SelfAuthAgreed,
];

impl Policy {
    fn name(self) -> &'static str {
        match self {
            Policy::Blind => "blind",
            Policy::BulletinOnly => "bulletin-only",
            Policy::SelfAuthAny => "self-auth, any hop",
            Policy::SelfAuthAgreed => "self-auth, agreed hop",
        }
    }
    fn holds(self) -> bool {
        matches!(self, Policy::SelfAuthAny | Policy::SelfAuthAgreed)
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Fate {
    At(f64),
    Expired,
    Open, // not delivered when the plan ends, TTL not yet run out
}

/// One sampled block of a flow: everything the flow generates in
/// [created, created + step), offered as a unit.
struct Job {
    src: usize,
    created: f64,
    bytes: f64,
    deadline: f64,
    undelivered: Fate,
}

/// A stretch of time during which the source transmits on one link.
#[derive(Clone, Copy)]
struct Seg {
    t0: f64,
    t1: f64,
    rate: f64,
    delay: f64,
    relay: usize,
}

/// One transmitter per source: in every instant, use the fastest usable link.
fn single_radio(cands: &[Seg]) -> Vec<Seg> {
    let mut cuts: Vec<f64> = cands.iter().flat_map(|c| [c.t0, c.t1]).collect();
    cuts.sort_by(|a, b| a.total_cmp(b));
    cuts.dedup();
    let mut out: Vec<Seg> = Vec::new();
    for w in cuts.windows(2) {
        let (a, b) = (w[0], w[1]);
        let best = cands
            .iter()
            .filter(|c| c.t0 <= a && c.t1 >= b)
            .max_by(|x, y| x.rate.total_cmp(&y.rate).then(y.relay.cmp(&x.relay)));
        if let Some(c) = best {
            if let Some(last) = out.last_mut() {
                if last.t1 == a
                    && last.relay == c.relay
                    && last.rate == c.rate
                    && last.delay == c.delay
                {
                    last.t1 = b;
                    continue;
                }
            }
            out.push(Seg { t0: a, t1: b, ..*c });
        }
    }
    out
}

struct Served {
    peak_backlog: f64,
    /// (from, until, bytes) held at the boundary awaiting authorization.
    held: Vec<(f64, f64, f64)>,
}

/// FIFO fluid service of one source's blocks over its usable links.
/// `release(relay)` is when that relay can authorize the source (0 for
/// policies that never hold). A block is delivered when its last byte arrives
/// and every relay that took part of it can authorize the source.
fn serve(
    jobs: &[Job],
    order: &[usize],
    segs: &[Seg],
    release: &dyn Fn(usize) -> f64,
    fate: &mut [Fate],
    last_hop: &mut [Option<(usize, f64)>],
) -> Served {
    let mut q: std::collections::VecDeque<(usize, f64, f64)> = std::collections::VecDeque::new();
    let mut next = 0usize;
    let mut backlog = 0.0f64;
    let mut peak = 0.0f64;
    let mut held = Vec::new();
    for &j in order {
        fate[j] = jobs[j].undelivered;
    }
    for seg in segs {
        let bps = seg.rate / 8.0;
        let mut t = seg.t0;
        loop {
            while next < order.len() && jobs[order[next]].created <= t {
                let j = order[next];
                q.push_back((j, jobs[j].bytes, 0.0));
                backlog += jobs[j].bytes;
                peak = peak.max(backlog);
                next += 1;
            }
            while let Some(&(j, rem, _)) = q.front() {
                if jobs[j].deadline <= t {
                    backlog -= rem;
                    q.pop_front();
                } else {
                    break;
                }
            }
            if q.is_empty() {
                if next < order.len() && jobs[order[next]].created < seg.t1 {
                    t = jobs[order[next]].created;
                    continue;
                }
                break;
            }
            // Serve up to the end of the segment or the next arrival,
            // whichever is first, so the backlog is exact at every arrival.
            let until = match order.get(next) {
                Some(&j) if jobs[j].created < seg.t1 => jobs[j].created,
                _ => seg.t1,
            };
            let cap = (until - t) * bps;
            let front = q.front_mut().unwrap();
            front.2 = front.2.max(release(seg.relay));
            if front.1 <= cap {
                let (j, rem, rel) = *front;
                q.pop_front();
                backlog -= rem;
                let tf = t + rem / bps;
                let arrival = tf + seg.delay;
                let done = arrival.max(rel);
                last_hop[j] = Some((seg.relay, arrival));
                if done < jobs[j].deadline {
                    fate[j] = Fate::At(done);
                }
                if rel > arrival {
                    held.push((arrival, rel.min(jobs[j].deadline), jobs[j].bytes));
                }
                t = tf;
            } else {
                front.1 -= cap;
                backlog -= cap;
                t = until;
                if until >= seg.t1 {
                    break;
                }
            }
        }
    }
    while next < order.len() {
        backlog += jobs[order[next]].bytes;
        peak = peak.max(backlog);
        next += 1;
    }
    Served {
        peak_backlog: peak,
        held,
    }
}

fn peak_of(intervals: &[(f64, f64, f64)]) -> f64 {
    let mut ev: Vec<(f64, f64)> = intervals
        .iter()
        .flat_map(|&(a, b, x)| [(a, x), (b, -x)])
        .collect();
    ev.sort_by(|x, y| x.0.total_cmp(&y.0).then(x.1.total_cmp(&y.1)));
    let (mut cur, mut peak) = (0.0f64, 0.0f64);
    for (_, d) in ev {
        cur += d;
        peak = peak.max(cur);
    }
    peak
}

struct Stats {
    latencies: Vec<f64>, // hours, delivered only
    expired: usize,
    open: usize,
}

impl Stats {
    fn new() -> Self {
        Stats {
            latencies: Vec::new(),
            expired: 0,
            open: 0,
        }
    }
    fn add(&mut self, created: f64, fate: Fate) {
        match fate {
            Fate::At(t) => self.latencies.push((t - created) / HOUR),
            Fate::Expired => self.expired += 1,
            Fate::Open => self.open += 1,
        }
    }
    fn sorted(&self) -> Vec<f64> {
        let mut v = self.latencies.clone();
        v.sort_by(|a, b| a.total_cmp(b));
        v
    }
    fn pct(&self, p: f64) -> f64 {
        let v = self.sorted();
        if v.is_empty() {
            return 0.0;
        }
        v[((v.len() - 1) as f64 * p).round() as usize]
    }
    fn mean(&self) -> f64 {
        if self.latencies.is_empty() {
            0.0
        } else {
            self.latencies.iter().sum::<f64>() / self.latencies.len() as f64
        }
    }
}

fn fmt_dur(h: f64) -> String {
    if h >= 48.0 {
        format!("{:.1} d", h / 24.0)
    } else if h >= 1.0 {
        format!("{:.1} h", h)
    } else {
        format!("{:.0} min", h * 60.0)
    }
}

fn fmt_bytes(b: f64) -> String {
    if b >= 1e9 {
        format!("{:.1} GB", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.1} MB", b / 1e6)
    } else {
        format!("{:.0} kB", b / 1e3)
    }
}

fn print_table(rows: &[(Policy, &Stats)]) {
    println!("  policy                  delivered  expired  open      mean     median        p90        max");
    for (p, s) in rows {
        println!(
            "  {:<23} {:>9}  {:>7}  {:>4}  {:>8}  {:>9}  {:>9}  {:>9}",
            p.name(),
            s.latencies.len(),
            s.expired,
            s.open,
            fmt_dur(s.mean()),
            fmt_dur(s.pct(0.5)),
            fmt_dur(s.pct(0.9)),
            fmt_dur(s.pct(1.0))
        );
    }
}

struct Opts {
    peer_day: f64,
    contacts: String,
    sample: f64,
    /// Overrides the spec's late provider in `cross-support`.
    late: Option<String>,
}

#[derive(Clone, Copy, PartialEq)]
enum Case {
    Federation,
    CrossSupport,
}

fn run(spec: &Spec, sc: &Scenario, case: Case, o: &Opts) {
    let n = sc.nodes.len();
    let t_peer = o.peer_day * DAY;
    let org_of = |i: usize| sc.nodes[i].org;
    let late_infra: Vec<usize> = match case {
        Case::Federation => (0..spec.orgs.len())
            .filter(|&k| spec.orgs[k].role == Role::Infrastructure)
            .collect(),
        Case::CrossSupport => {
            let want = o.late.as_deref().unwrap_or(spec.cross_support_late);
            match spec.orgs.iter().position(|g| {
                g.role == Role::Infrastructure && (g.name == want || g.name.ends_with(want))
            }) {
                Some(k) => vec![k],
                None => {
                    eprintln!(
                        "--late {}: no infrastructure collective of that name in {}",
                        want, spec.key
                    );
                    std::process::exit(2)
                }
            }
        }
    };

    println!("==============================================================");
    println!(
        "scenario: {} {} ({} contacts), case: {}, agreement day {}",
        spec.title,
        VERSION,
        o.contacts,
        if case == Case::Federation {
            "federation"
        } else {
            "cross-support"
        },
        o.peer_day
    );
    println!("==============================================================");
    for note in &sc.notes {
        println!("note: {}", note);
    }

    // ---- topology and boundary sources ---------------------------------------
    let mut out: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (ci, c) in sc.contacts.iter().enumerate() {
        out[c.from].push(ci);
    }
    let boundary_src: Vec<bool> = (0..n)
        .map(|s| {
            let nb: HashSet<usize> = out[s].iter().map(|&ci| sc.contacts[ci].to).collect();
            !nb.is_empty() && nb.iter().all(|&r| org_of(r) != org_of(s))
        })
        .collect();

    let cross = sc
        .contacts
        .iter()
        .filter(|c| org_of(c.from) != org_of(c.to))
        .count();
    println!(
        "{} nodes in {} collectives, {:.1} days, {} directional contacts ({} cross-collective)",
        n,
        spec.orgs.len(),
        sc.horizon / DAY,
        sc.contacts.len(),
        cross
    );
    for (k, g) in spec.orgs.iter().enumerate() {
        let peering = if g.role == Role::Mission {
            "mission".to_string()
        } else if late_infra.contains(&k) {
            format!("infrastructure, agrees with missions on day {}", o.peer_day)
        } else {
            "infrastructure, pre-peered with missions".to_string()
        };
        println!("  {:<19} {:<30} {}", g.name, g.members.join(" "), peering);
    }
    println!();

    // ---- collectives, identities, bulletins ----------------------------------
    let mut auth: Vec<Authority<Sig>> = spec
        .orgs
        .iter()
        .enumerate()
        .map(|(k, g)| Authority::<Sig>::new(g.name, &[40 + k as u8; 32]))
        .collect();
    let roots: Vec<Vec<u8>> = auth.iter().map(|a| a.root_public_key().to_vec()).collect();
    let identities: Vec<Identity<Sig>> = (0..n)
        .map(|i| {
            Identity::<Sig>::incept_with_ipn(&seed_bytes(i, 1), &seed_bytes(i, 2), sc.nodes[i].ipn)
        })
        .collect();
    let ids: Vec<NodeId> = identities.iter().map(|id| id.node_id()).collect();
    let name_of = |i: usize| SourceName::Ipn(sc.nodes[i].ipn);
    let members_of = |k: usize| -> Vec<usize> { (0..n).filter(|&i| org_of(i) == k).collect() };
    let issuers_of = |k: usize| -> Vec<usize> {
        spec.orgs[k]
            .issuers
            .iter()
            .map(|l| sc.nodes.iter().position(|x| x.label == *l).unwrap())
            .collect()
    };

    let mut bulletins: Vec<Bulletin> = Vec::new();
    let mut inject: Vec<Vec<(usize, f64)>> = Vec::new();
    let mut member_b = vec![0usize; n];
    for i in 0..n {
        member_b[i] = bulletins.len();
        bulletins.push(auth[org_of(i)].announce_member(&ids[i], Some(sc.nodes[i].ipn), &[]));
        inject.push(
            members_of(org_of(i))
                .into_iter()
                .map(|m| (m, 0.0))
                .collect(),
        );
    }
    // Peering, both directions. Early pairs are provisioned before deployment
    // (each side's nodes carry the grant and the peer's member list); late
    // pairs are agreed on the ground on the agreement day and must flood out.
    // Missions do not peer with each other: no scored flow needs it.
    for a in 0..spec.orgs.len() {
        for b in (a + 1)..spec.orgs.len() {
            let (ra, rb) = (spec.orgs[a].role, spec.orgs[b].role);
            if ra == Role::Mission && rb == Role::Mission {
                continue;
            }
            let late = (ra == Role::Mission && late_infra.contains(&b))
                || (rb == Role::Mission && late_infra.contains(&a));
            for (x, y) in [(a, b), (b, a)] {
                let (at, holders) = if late {
                    (t_peer, issuers_of(x))
                } else {
                    (0.0, members_of(x))
                };
                bulletins.push(auth[x].announce_peer(spec.orgs[y].name, &roots[y]));
                inject.push(holders.iter().map(|&h| (h, at)).collect());
                for m in members_of(y) {
                    inject[member_b[m]].extend(holders.iter().map(|&h| (h, at)));
                }
            }
        }
    }

    // ---- flood, then replay arrivals into each node's trust store ------------
    let arrivals: Vec<Vec<f64>> = inject.iter().map(|src| flood(sc, &out, src)).collect();
    let sources: Vec<usize> = (0..n).filter(|&s| boundary_src[s]).collect();
    // auth_at[(r, s)]: first time r can authorize s.
    // known_at[(s, k)]: first time s's own trust store lists collective k as
    // a peer, i.e. when the sender itself learns of the agreement.
    let mut auth_at: HashMap<(usize, usize), f64> = HashMap::new();
    let mut known_at: HashMap<(usize, usize), f64> = HashMap::new();
    let arrivals_at = |r: usize| -> Vec<(f64, usize)> {
        let mut ev: Vec<(f64, usize)> = (0..bulletins.len())
            .filter(|&bi| arrivals[bi][r].is_finite())
            .map(|bi| (arrivals[bi][r], bi))
            .collect();
        ev.sort_by(|x, y| x.0.total_cmp(&y.0).then(x.1.cmp(&y.1)));
        ev
    };
    for r in 0..n {
        let ev = arrivals_at(r);
        let (_, dk) = Kem::keygen(&seed_bytes(r, 3));
        let mut rx = Receiver::<Kem>::new(
            TrustStore::new(spec.orgs[org_of(r)].name, &roots[org_of(r)]),
            dk,
        );
        let mut pending = Vec::new();
        let mut k = 0;
        while k < ev.len() {
            let t = ev[k].0;
            while k < ev.len() && ev[k].0 == t {
                pending.push(ev[k].1);
                k += 1;
            }
            apply_pending(&mut rx, &mut pending, &bulletins);
            for &s in &sources {
                if org_of(s) != org_of(r)
                    && !auth_at.contains_key(&(r, s))
                    && rx.trust().authorize(&ids[s], &name_of(s)).is_ok()
                {
                    auth_at.insert((r, s), t);
                }
            }
            if boundary_src[r] {
                let peers: Vec<String> = rx.trust().peers().iter().map(|p| p.to_string()).collect();
                for (kk, g) in spec.orgs.iter().enumerate() {
                    if peers.iter().any(|p| p == g.name) {
                        known_at.entry((r, kk)).or_insert(t);
                    }
                }
            }
        }
    }
    let auth_time = |r: usize, s: usize| auth_at.get(&(r, s)).copied().unwrap_or(f64::INFINITY);
    let known_time = |s: usize, r: usize| {
        known_at
            .get(&(s, org_of(r)))
            .copied()
            .unwrap_or(f64::INFINITY)
    };

    // ---- traffic --------------------------------------------------------------
    let mut jobs: Vec<Job> = Vec::new();
    let mut excluded: Vec<&str> = Vec::new();
    println!("flows scored (every next hop of the source is in another collective)");
    println!(
        "  {:<34} {:>7} {:>6} {:>7} {:>9} {:>5} {:>8}  first-hop links",
        "flow", "ADU B", "every", "blocks", "rate", "TTL", "sig/ADU"
    );
    for f in &sc.flows {
        if !boundary_src[f.src] {
            excluded.push(&f.info);
            continue;
        }
        let step = f.interval.max(o.sample);
        let per_block = step / f.interval * (f.adu + STEADY_OVERHEAD_B);
        let mut t = f.start;
        let mut count = 0;
        while t < f.end && t < sc.horizon {
            let expiry = t + f.ttl;
            jobs.push(Job {
                src: f.src,
                created: t,
                bytes: per_block,
                deadline: expiry.min(sc.horizon),
                undelivered: if expiry <= sc.horizon {
                    Fate::Expired
                } else {
                    Fate::Open
                },
            });
            count += 1;
            t += step;
        }
        let mut links: Vec<String> = out[f.src]
            .iter()
            .map(|&ci| {
                format!(
                    "{} {}",
                    sc.nodes[sc.contacts[ci].to].label,
                    rate_str(sc.contacts[ci].rate)
                )
            })
            .collect();
        links.sort();
        links.dedup();
        println!(
            "  {:<34} {:>7} {:>5}s {:>7} {:>9} {:>3} d {:>7.1}%  {}{}",
            f.info,
            f.adu as u64,
            f.interval,
            count,
            rate_str((f.adu + STEADY_OVERHEAD_B) * 8.0 / f.interval),
            f.ttl / DAY,
            STEADY_OVERHEAD_B / f.adu * 100.0,
            links.join(", "),
            if f.ttl_filled { "  (ttl filled)" } else { "" }
        );
    }
    println!(
        "  one block per flow every max(interval, {} min); rate includes the ML-DSA-65 signature",
        o.sample / 60.0
    );
    if !excluded.is_empty() {
        println!(
            "  excluded, no trust boundary at the first hop: {}",
            excluded.join("; ")
        );
    }
    println!();

    // ---- serve each source under each policy ---------------------------------
    let mut fate: HashMap<Policy, Vec<Fate>> = HashMap::new();
    let mut hop: HashMap<Policy, Vec<Option<(usize, f64)>>> = HashMap::new();
    let mut peak_src: BTreeMap<(usize, usize), f64> = BTreeMap::new(); // (source, policy idx)
    let mut peak_held: BTreeMap<(usize, usize), f64> = BTreeMap::new();
    for (pi, &p) in POLICIES.iter().enumerate() {
        let mut fv = vec![Fate::Open; jobs.len()];
        let mut hv = vec![None; jobs.len()];
        for &s in &sources {
            let mut order: Vec<usize> = (0..jobs.len()).filter(|&j| jobs[j].src == s).collect();
            if order.is_empty() {
                continue;
            }
            order.sort_by(|&a, &b| jobs[a].created.total_cmp(&jobs[b].created).then(a.cmp(&b)));
            let cands: Vec<Seg> = out[s]
                .iter()
                .filter_map(|&ci| {
                    let c = &sc.contacts[ci];
                    let from = match p {
                        Policy::Blind | Policy::SelfAuthAny => c.start,
                        Policy::BulletinOnly => c.start.max(auth_time(c.to, s)),
                        Policy::SelfAuthAgreed => c.start.max(known_time(s, c.to)),
                    };
                    (from < c.end).then_some(Seg {
                        t0: from,
                        t1: c.end,
                        rate: c.rate,
                        delay: c.delay,
                        relay: c.to,
                    })
                })
                .collect();
            let segs = single_radio(&cands);
            let release = |r: usize| if p.holds() { auth_time(r, s) } else { 0.0 };
            let served = serve(&jobs, &order, &segs, &release, &mut fv, &mut hv);
            peak_src.insert((s, pi), served.peak_backlog);
            peak_held.insert((s, pi), peak_of(&served.held));
        }
        fate.insert(p, fv);
        hop.insert(p, hv);
    }

    // In window: under any-hop transmission, the hop that took the block
    // could not yet authorize its source when it arrived.
    let in_window: Vec<bool> = (0..jobs.len())
        .map(|j| match hop[&Policy::Blind][j] {
            Some((r, a)) => auth_time(r, jobs[j].src) > a,
            None => false,
        })
        .collect();

    // Real bundles for the any-hop self-auth path. Each receiver sees its
    // bulletin arrivals and bundle arrivals interleaved in time order, so its
    // own verdict at each arrival must match the trust replay above.
    let mut real_rx: Vec<Receiver<Kem>> = (0..n)
        .map(|i| {
            let (_, dk) = Kem::keygen(&seed_bytes(i, 4));
            Receiver::new(
                TrustStore::new(spec.orgs[org_of(i)].name, &roots[org_of(i)]),
                dk,
            )
        })
        .collect();
    let mut accepted: HashMap<(usize, usize), usize> = HashMap::new();
    let mut held_at_accept = 0usize;
    for (r, rx) in real_rx.iter_mut().enumerate() {
        // (time, 0 = bulletin / 1 = bundle, index); bulletins first on ties.
        let mut ev: Vec<(f64, u8, usize)> = arrivals_at(r)
            .into_iter()
            .map(|(t, bi)| (t, 0, bi))
            .collect();
        for (j, h) in hop[&Policy::SelfAuthAny].iter().enumerate() {
            if let Some((rr, a)) = *h {
                if rr == r {
                    ev.push((a, 1, j));
                }
            }
        }
        ev.sort_by(|x, y| x.0.total_cmp(&y.0).then(x.1.cmp(&y.1)).then(x.2.cmp(&y.2)));
        let mut pending = Vec::new();
        for (t, kind, idx) in ev {
            if kind == 0 {
                pending.push(idx);
                apply_pending(rx, &mut pending, &bulletins);
                continue;
            }
            let s = jobs[idx].src;
            let bundle = Sender::new(&identities[s], name_of(s)).send_plain(b"block");
            assert_eq!(
                verify_binding::<Sig>(&bundle).expect("binding verifies from the bundle alone"),
                ids[s]
            );
            let verdict = rx.accept_at::<Sig>(&bundle, t as u64).expect("accept");
            assert!(verdict.binding_verified);
            assert_eq!(
                verdict.is_authorized(),
                auth_time(r, s) <= t,
                "trust replay and receiver disagree"
            );
            if !verdict.is_authorized() {
                held_at_accept += 1;
            }
            *accepted.entry((r, s)).or_default() += 1;
        }
    }

    // ---- windows per (receiver, sender) ----------------------------------------
    println!("per (receiver <- sender): first contact, when the sender knows of the agreement,");
    println!("when the receiver can authorize; 'lag' is the window an agreed-hop sender can use");
    let mut first_contact: BTreeMap<(usize, usize), f64> = BTreeMap::new();
    for c in &sc.contacts {
        if boundary_src[c.from] && org_of(c.to) != org_of(c.from) {
            let e = first_contact.entry((c.to, c.from)).or_insert(c.start);
            *e = e.min(c.start);
        }
    }
    let day = |t: f64| {
        if t.is_finite() {
            format!("{:.2}", t / DAY)
        } else {
            "never".to_string()
        }
    };
    println!(
        "  {:<15} {:>14} {:>12} {:>14} {:>10}",
        "pair", "first contact", "sender knows", "receiver auth", "lag"
    );
    for (&(r, s), &fc) in &first_contact {
        let (k, a) = (known_time(s, r), auth_time(r, s));
        let lag = if a.is_finite() && k.is_finite() && a > k {
            fmt_dur((a - k) / HOUR)
        } else {
            "0".to_string()
        };
        println!(
            "  {:<15} {:>14} {:>12} {:>14} {:>10}",
            format!("{} <- {}", sc.nodes[r].label, sc.nodes[s].label),
            format!("day {}", day(fc)),
            day(k),
            day(a),
            lag
        );
    }
    println!();

    // ---- summary ------------------------------------------------------------
    let stats = |sel: &dyn Fn(usize) -> bool, p: Policy| -> Stats {
        let mut st = Stats::new();
        for j in 0..jobs.len() {
            if sel(j) {
                st.add(jobs[j].created, fate[&p][j]);
            }
        }
        st
    };
    let all: Vec<Stats> = POLICIES.iter().map(|&p| stats(&|_| true, p)).collect();
    let win: Vec<Stats> = POLICIES
        .iter()
        .map(|&p| stats(&|j| in_window[j], p))
        .collect();
    let n_win = in_window.iter().filter(|&&w| w).count();
    println!(
        "all {} blocks, latency to acceptance at the boundary",
        jobs.len()
    );
    print_table(
        &POLICIES
            .iter()
            .zip(all.iter())
            .map(|(&p, s)| (p, s))
            .collect::<Vec<_>>(),
    );
    println!();
    println!(
        "the {} blocks that reached a hop not yet able to authorize the source (in window)",
        n_win
    );
    print_table(
        &POLICIES
            .iter()
            .zip(win.iter())
            .map(|(&p, s)| (p, s))
            .collect::<Vec<_>>(),
    );
    println!();

    println!("by source: in-window mean latency | peak backlog at the source | peak held at the boundary");
    println!(
        "  {:<6} {:>6}   {:>9} {:>9} {:>9} {:>9}   {:>9} {:>9} {:>9} {:>9}   {:>9} {:>9}",
        "source",
        "blocks",
        "blind",
        "bull-only",
        "sa-any",
        "sa-agreed",
        "blind",
        "bull-only",
        "sa-any",
        "sa-agreed",
        "sa-any",
        "sa-agreed"
    );
    for &s in &sources {
        let k = (0..jobs.len())
            .filter(|&j| jobs[j].src == s && in_window[j])
            .count();
        let lat: Vec<String> = POLICIES
            .iter()
            .map(|&p| {
                let st = stats(&|j| jobs[j].src == s && in_window[j], p);
                if k == 0 {
                    "-".to_string()
                } else {
                    fmt_dur(st.mean())
                }
            })
            .collect();
        let pk: Vec<String> = (0..4)
            .map(|pi| fmt_bytes(peak_src.get(&(s, pi)).copied().unwrap_or(0.0)))
            .collect();
        let hd: Vec<String> = (2..4)
            .map(|pi| fmt_bytes(peak_held.get(&(s, pi)).copied().unwrap_or(0.0)))
            .collect();
        println!(
            "  {:<6} {:>6}   {:>9} {:>9} {:>9} {:>9}   {:>9} {:>9} {:>9} {:>9}   {:>9} {:>9}",
            sc.nodes[s].label,
            k,
            lat[0],
            lat[1],
            lat[2],
            lat[3],
            pk[0],
            pk[1],
            pk[2],
            pk[3],
            hd[0],
            hd[1]
        );
    }
    println!();

    for p in [Policy::SelfAuthAny, Policy::SelfAuthAgreed] {
        let (mut earlier, mut same, mut later) = (Vec::new(), 0usize, Vec::new());
        let (mut only_sa, mut only_bo) = (0usize, 0usize);
        for (fs, fb) in fate[&p].iter().zip(fate[&Policy::BulletinOnly].iter()) {
            match (*fs, *fb) {
                (Fate::At(a), Fate::At(b)) => {
                    // One-second resolution: the fluid model's float sums
                    // differ in the last bits between policies.
                    if b - a >= 1.0 {
                        earlier.push((b - a) / HOUR)
                    } else if a - b >= 1.0 {
                        later.push((a - b) / HOUR)
                    } else {
                        same += 1
                    }
                }
                (Fate::At(_), _) => only_sa += 1,
                (_, Fate::At(_)) => only_bo += 1,
                _ => {}
            }
        }
        let summ = |v: &mut Vec<f64>| -> String {
            if v.is_empty() {
                return String::new();
            }
            v.sort_by(|a, b| a.total_cmp(b));
            format!(
                "   mean {}  median {}  max {}",
                fmt_dur(v.iter().sum::<f64>() / v.len() as f64),
                fmt_dur(v[v.len() / 2]),
                fmt_dur(*v.last().unwrap())
            )
        };
        println!("{} vs bulletin-only, per block", p.name());
        println!(
            "  earlier ....... {:>6}{}",
            earlier.len(),
            summ(&mut earlier)
        );
        println!("  same time ..... {:>6}", same);
        println!("  later ......... {:>6}{}", later.len(), summ(&mut later));
        if only_sa + only_bo > 0 {
            println!(
                "  delivered only under self-auth {}, only under bulletin-only {}",
                only_sa, only_bo
            );
        }
    }

    // ---- promotion check on the real receivers ---------------------------------
    // Every receiver has now seen every bulletin that reached it in the plan.
    let (mut promoted, mut pairs_ok, mut never) = (0usize, 0usize, 0usize);
    for (&(r, s), &k) in &accepted {
        if real_rx[r].authorization(&ids[s], &name_of(s)).is_ok() {
            let p = real_rx[r].promotable_history(&ids[s]).len();
            assert_eq!(
                p,
                k.min(MAX_HISTORY_PER_SOURCE),
                "held history must promote in full"
            );
            promoted += p;
            pairs_ok += 1;
        } else {
            assert!(!auth_at.contains_key(&(r, s)));
            never += 1;
        }
    }
    println!(
        "promotion check (real receivers, any-hop path): {} bundles accepted while unauthorized; {} promotable across {} pairs{}",
        held_at_accept,
        promoted,
        pairs_ok,
        if never > 0 { format!(", {} pairs never authorized within the plan", never) } else { String::new() }
    );
    println!();

    // ---- latency CDF, pgfplots-ready ------------------------------------------
    println!(
        "latency CDF over the {} in-window blocks (days, fraction delivered), for pgfplots",
        n_win
    );
    for (pi, &p) in POLICIES.iter().enumerate() {
        let v = win[pi].sorted();
        let total = n_win.max(1) as f64;
        let mut pts: BTreeMap<u64, f64> = BTreeMap::new();
        for (i, h) in v.iter().enumerate() {
            pts.insert((*h / 24.0 * 10.0).round() as u64, (i + 1) as f64 / total);
        }
        let mut line: Vec<String> = vec!["(0,0)".to_string()];
        line.extend(
            pts.iter()
                .map(|(d, f)| format!("({:.1},{:.3})", *d as f64 / 10.0, f)),
        );
        println!("  {}: {}", p.name(), line.join(" "));
    }
    println!();
}

fn rate_str(bps: f64) -> String {
    if bps >= 1e6 {
        format!("{:.0} Mbps", bps / 1e6)
    } else if bps >= 1e3 {
        format!("{:.0} kbps", bps / 1e3)
    } else {
        format!("{:.0} bps", bps)
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: refscenario [lunar|mars|all] [--case federation|cross-support|all] [--peer-day D] \
         [--contacts actual|planned] [--sample-min M] [--late orange|blue] [--dir PATH]"
    );
    std::process::exit(2)
}

fn main() {
    let mut which = "all".to_string();
    let mut case = "all".to_string();
    let mut opts = Opts {
        peer_day: 10.0,
        contacts: "actual".into(),
        sample: HOUR,
        late: None,
    };
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scenarios")
        .join("ccsds");

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    let val = |i: usize| -> String { args.get(i + 1).cloned().unwrap_or_else(|| usage()) };
    let num = |i: usize| -> f64 { val(i).parse().unwrap_or_else(|_| usage()) };
    while i < args.len() {
        match args[i].as_str() {
            "--case" => {
                case = val(i);
                i += 1;
            }
            "--peer-day" => {
                opts.peer_day = num(i);
                i += 1;
            }
            "--contacts" => {
                opts.contacts = val(i);
                i += 1;
            }
            "--sample-min" => {
                opts.sample = num(i) * 60.0;
                i += 1;
            }
            "--late" => {
                opts.late = Some(val(i));
                i += 1;
            }
            "--dir" => {
                dir = PathBuf::from(val(i));
                i += 1;
            }
            "-h" | "--help" => usage(),
            s if !s.starts_with('-') => which = s.to_string(),
            _ => usage(),
        }
        i += 1;
    }
    if !(opts.sample > 0.0 && opts.peer_day >= 0.0) {
        usage();
    }
    let contacts_file = match opts.contacts.as_str() {
        "actual" => "actual_contacts.csv",
        "planned" => "planned_contacts.csv",
        _ => usage(),
    };
    let specs: Vec<&Spec> = match which.as_str() {
        "lunar" => vec![&LUNAR],
        "mars" => vec![&MARS],
        "all" => vec![&LUNAR, &MARS],
        "leo" => {
            eprintln!("low-earth-orbit has a single operator: no trust boundary to measure.");
            std::process::exit(0)
        }
        _ => usage(),
    };
    let cases: Vec<Case> = match case.as_str() {
        "federation" => vec![Case::Federation],
        "cross-support" => vec![Case::CrossSupport],
        "all" => vec![Case::Federation, Case::CrossSupport],
        _ => usage(),
    };

    println!("\"DTN Reference Scenarios\" by CCSDS, CC BY 4.0 (scenarios/ccsds/README.md)\n");
    for spec in specs {
        let sc = match load(&dir, spec, contacts_file) {
            Ok(sc) => sc,
            Err(e) => {
                eprintln!("{}: {}", spec.key, e);
                std::process::exit(1)
            }
        };
        for &c in &cases {
            run(spec, &sc, c, &opts);
        }
    }
}
