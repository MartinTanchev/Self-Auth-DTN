//! Contact-plan simulation with a retransmission baseline.
//!
//! Unlike `coverage` (random epidemic contacts), every contact here is
//! scheduled: two agencies, each with a ground station, a relay orbiter and
//! surface assets, cross-supporting each other's assets the way LunaNet's
//! multi-provider case expects. Bulletins move only over those contacts.
//!
//! Three receiver policies are scored on the same traffic and the same
//! bulletin flood:
//!
//!   blind          accept unauthenticated at first contact (insecure floor)
//!   bulletin-only  reject until a bulletin authorizes the sender; the sender
//!                  re-offers the bundle at every later cross-collective
//!                  contact until accepted or expired (optimistic baseline:
//!                  it assumes the sender learns of the rejection at once)
//!   self-auth      verify binding from the bundle, hold at the receiver,
//!                  deliver the moment the receiver can authorize
//!
//! Delivery is measured at the boundary: the first node of the other
//! collective that accepts the bundle. Forwarding inside the destination
//! collective is identical under every policy and is not modelled.
//!
//! Run with:  cargo run --release --example contactplan
//!            cargo run --release --example contactplan -- lunar
//!            cargo run --release --example contactplan -- mars

// Node-indexed loops read closer to the graph notation than iterators here.
#![allow(clippy::needless_range_loop)]

use self_auth_dtn::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};

type Sig = MockSig;
type Kem = MockKem;

const MIN: u64 = 1;
const HOUR: u64 = 60 * MIN;
const DAY: u64 = 24 * HOUR;

// Wire cost, ML-DSA-65 figures from `overhead`.
const PAYLOAD_B: u64 = 1024;
const STEADY_OVERHEAD_B: u64 = 3309;
const FIRST_CONTACT_OVERHEAD_B: u64 = 8618;

fn seed_bytes(i: usize, tag: u8) -> [u8; 32] {
    let mut s = [tag; 32];
    s[0] = i as u8;
    s[1] = (i >> 8) as u8;
    s
}

// ---------------------------------------------------------------------------
// Contact plan
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Contact {
    t: u64, // start, minutes
    dur: u64,
    a: usize,
    b: usize,
}

/// A periodic link: `dur` minutes every `period`, first at `offset`, between
/// `from` and `until` (both minutes from deployment).
struct Link {
    a: usize,
    b: usize,
    period: u64,
    dur: u64,
    offset: u64,
    from: u64,
    label: &'static str,
}

fn expand(links: &[Link], horizon: u64) -> Vec<Contact> {
    let mut v = Vec::new();
    for l in links {
        let mut t = l.offset;
        while t < horizon {
            if t >= l.from {
                v.push(Contact {
                    t,
                    dur: l.dur,
                    a: l.a,
                    b: l.b,
                });
            }
            t += l.period;
        }
    }
    v.sort_by_key(|c| (c.t, c.a, c.b));
    v
}

struct Plan {
    name: &'static str,
    horizon: u64,
    lifetime: u64,
    gen_every: u64,
    t_peer: u64,
    t_enrol: u64,
    links: Vec<Link>,
}

// Node indices, fixed for both plans.
const GS_A: usize = 0;
const ORB_A: usize = 1;
const ROV_A1: usize = 2;
const ROV_A2: usize = 3;
const GS_B: usize = 4;
const ORB_B: usize = 5;
const ROV_B1: usize = 6;
const LND_B: usize = 7;
const N: usize = 8;
const NAMES: [&str; N] = [
    "gs-a", "orb-a", "rov-a1", "rov-a2", "gs-b", "orb-b", "rov-b1", "lnd-b",
];
fn collective(i: usize) -> &'static str {
    if i < GS_B {
        "agency-a"
    } else {
        "agency-b"
    }
}

/// Lunar: relay orbiters in low lunar orbit, one ground allocation per
/// orbiter per day, cross-support passes twice a day, rovers meet weekly.
fn lunar() -> Plan {
    let t_enrol = 30 * DAY;
    Plan {
        name: "lunar (dense)",
        horizon: 60 * DAY,
        lifetime: 14 * DAY,
        gen_every: 6 * HOUR,
        t_peer: 10 * DAY,
        t_enrol,
        links: vec![
            Link {
                a: GS_A,
                b: GS_B,
                period: HOUR,
                dur: HOUR,
                offset: 0,
                from: 0,
                label: "ground, terrestrial",
            },
            Link {
                a: GS_A,
                b: ORB_A,
                period: DAY,
                dur: 6 * HOUR,
                offset: 0,
                from: 0,
                label: "ground pass A",
            },
            Link {
                a: GS_B,
                b: ORB_B,
                period: DAY,
                dur: 6 * HOUR,
                offset: 12 * HOUR,
                from: 0,
                label: "ground pass B",
            },
            Link {
                a: ORB_A,
                b: ROV_A1,
                period: 6 * HOUR,
                dur: 8 * MIN,
                offset: 40 * MIN,
                from: 0,
                label: "own relay",
            },
            Link {
                a: ORB_A,
                b: ROV_A2,
                period: 6 * HOUR,
                dur: 8 * MIN,
                offset: 100 * MIN,
                from: 0,
                label: "own relay",
            },
            Link {
                a: ORB_B,
                b: ROV_B1,
                period: 6 * HOUR,
                dur: 8 * MIN,
                offset: 220 * MIN,
                from: 0,
                label: "own relay",
            },
            Link {
                a: ORB_B,
                b: LND_B,
                period: 6 * HOUR,
                dur: 8 * MIN,
                offset: 280 * MIN,
                from: t_enrol,
                label: "own relay",
            },
            Link {
                a: ORB_B,
                b: ROV_A1,
                period: 12 * HOUR,
                dur: 8 * MIN,
                offset: 5 * HOUR,
                from: 0,
                label: "cross-support",
            },
            Link {
                a: ORB_A,
                b: ROV_B1,
                period: 12 * HOUR,
                dur: 8 * MIN,
                offset: 8 * HOUR,
                from: 0,
                label: "cross-support",
            },
            Link {
                a: ORB_A,
                b: LND_B,
                period: 12 * HOUR,
                dur: 8 * MIN,
                offset: 9 * HOUR,
                from: t_enrol,
                label: "cross-support",
            },
            Link {
                a: ROV_A2,
                b: ROV_B1,
                period: 7 * DAY,
                dur: 30 * MIN,
                offset: 3 * DAY,
                from: 0,
                label: "surface encounter",
            },
        ],
    }
}

/// Mars: DSN contention gives each orbiter one hour every two days, relay
/// passes twice a day, cross-support every two days, rovers meet every ten.
fn mars() -> Plan {
    let t_enrol = 30 * DAY;
    Plan {
        name: "mars (sparse)",
        horizon: 90 * DAY,
        lifetime: 30 * DAY,
        gen_every: 12 * HOUR,
        t_peer: 10 * DAY,
        t_enrol,
        links: vec![
            Link {
                a: GS_A,
                b: GS_B,
                period: HOUR,
                dur: HOUR,
                offset: 0,
                from: 0,
                label: "ground, terrestrial",
            },
            Link {
                a: GS_A,
                b: ORB_A,
                period: 2 * DAY,
                dur: HOUR,
                offset: 0,
                from: 0,
                label: "DSN pass A",
            },
            Link {
                a: GS_B,
                b: ORB_B,
                period: 2 * DAY,
                dur: HOUR,
                offset: DAY,
                from: 0,
                label: "DSN pass B",
            },
            Link {
                a: ORB_A,
                b: ROV_A1,
                period: 12 * HOUR,
                dur: 8 * MIN,
                offset: 40 * MIN,
                from: 0,
                label: "own relay",
            },
            Link {
                a: ORB_A,
                b: ROV_A2,
                period: 12 * HOUR,
                dur: 8 * MIN,
                offset: 100 * MIN,
                from: 0,
                label: "own relay",
            },
            Link {
                a: ORB_B,
                b: ROV_B1,
                period: 12 * HOUR,
                dur: 8 * MIN,
                offset: 220 * MIN,
                from: 0,
                label: "own relay",
            },
            Link {
                a: ORB_B,
                b: LND_B,
                period: 12 * HOUR,
                dur: 8 * MIN,
                offset: 280 * MIN,
                from: t_enrol,
                label: "own relay",
            },
            Link {
                a: ORB_B,
                b: ROV_A1,
                period: 2 * DAY,
                dur: 8 * MIN,
                offset: 5 * HOUR,
                from: 0,
                label: "cross-support",
            },
            Link {
                a: ORB_A,
                b: ROV_B1,
                period: 2 * DAY,
                dur: 8 * MIN,
                offset: 8 * HOUR,
                from: 0,
                label: "cross-support",
            },
            Link {
                a: ORB_A,
                b: LND_B,
                period: 2 * DAY,
                dur: 8 * MIN,
                offset: 9 * HOUR,
                from: t_enrol,
                label: "cross-support",
            },
            Link {
                a: ROV_A2,
                b: ROV_B1,
                period: 10 * DAY,
                dur: 30 * MIN,
                offset: 3 * DAY,
                from: 0,
                label: "surface encounter",
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

struct SimNode {
    identity: Identity<Sig>,
    rx: Receiver<Kem>,
    carried: Vec<Bulletin>,
    have: HashSet<(String, u64)>,
    applied: HashSet<(String, u64)>,
    fielded_at: u64,
}

impl SimNode {
    fn new(idx: usize, root_key: &[u8], fielded_at: u64) -> Self {
        let identity = Identity::<Sig>::incept(
            &seed_bytes(idx, 1),
            &seed_bytes(idx, 2),
            NAMES[idx].as_bytes(),
        );
        let (_, dk) = Kem::keygen(&seed_bytes(idx, 3));
        SimNode {
            identity,
            rx: Receiver::new(TrustStore::new(collective(idx), root_key), dk),
            carried: Vec::new(),
            have: HashSet::new(),
            applied: HashSet::new(),
            fielded_at,
        }
    }

    fn add_bulletins(&mut self, incoming: &[Bulletin]) {
        for b in incoming {
            if self.have.insert((b.issuer.clone(), b.seq)) {
                self.carried.push(b.clone());
            }
        }
        loop {
            let mut progress = false;
            let mut pending: Vec<Bulletin> = self
                .carried
                .iter()
                .filter(|b| !self.applied.contains(&(b.issuer.clone(), b.seq)))
                .cloned()
                .collect();
            pending.sort_by(|x, y| (x.issuer.as_str(), x.seq).cmp(&(y.issuer.as_str(), y.seq)));
            for b in pending {
                if self.rx.apply_bulletin::<Sig>(&b).is_ok() {
                    self.applied.insert((b.issuer.clone(), b.seq));
                    progress = true;
                }
            }
            if !progress {
                break;
            }
        }
    }

    fn can_authorize(&self, id: &NodeId) -> bool {
        self.rx
            .trust()
            .authorize(id, &SourceName::SelfCertifying)
            .is_ok()
    }
}

// ---------------------------------------------------------------------------
// Traffic and scoring
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Outcome {
    delivered_at: Option<u64>, // None = expired
    transmissions: u64,
    bytes: u64,
}

struct Stats {
    latencies: Vec<f64>, // hours, delivered only
    expired: usize,
    transmissions: u64,
    bytes: u64,
}

impl Stats {
    fn new() -> Self {
        Stats {
            latencies: Vec::new(),
            expired: 0,
            transmissions: 0,
            bytes: 0,
        }
    }
    fn add(&mut self, created: u64, o: &Outcome) {
        match o.delivered_at {
            Some(t) => self.latencies.push((t - created) as f64 / HOUR as f64),
            None => self.expired += 1,
        }
        self.transmissions += o.transmissions;
        self.bytes += o.bytes;
    }
    fn pct(&self, p: f64) -> f64 {
        if self.latencies.is_empty() {
            return 0.0;
        }
        let mut v = self.latencies.clone();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let idx = ((v.len() - 1) as f64 * p).round() as usize;
        v[idx]
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
    } else {
        format!("{:.1} h", h)
    }
}

fn run(plan: &Plan) {
    println!("==============================================================");
    println!("plan: {}", plan.name);
    println!("==============================================================");

    let contacts = expand(&plan.links, plan.horizon);
    let cross: Vec<&Contact> = contacts
        .iter()
        .filter(|c| collective(c.a) != collective(c.b))
        .collect();
    println!(
        "{} nodes, {} days, {} scheduled contacts ({} cross-collective, {} of them ground-to-ground)",
        N,
        plan.horizon / DAY,
        contacts.len(),
        cross.len(),
        cross.iter().filter(|c| c.a == GS_A && c.b == GS_B).count()
    );
    println!(
        "peering agreed day {}, lander enrolled day {}, bundle lifetime {} days",
        plan.t_peer / DAY,
        plan.t_enrol / DAY,
        plan.lifetime / DAY
    );
    println!();
    println!("links");
    for l in &plan.links {
        println!(
            "  {:<7} <-> {:<7} {:>4} min every {:>5.1} h   {}",
            NAMES[l.a],
            NAMES[l.b],
            l.dur,
            l.period as f64 / HOUR as f64,
            l.label
        );
    }
    println!();

    // ---- collectives, identities, provisioning ----------------------------
    let mut agency_a = Authority::<Sig>::new("agency-a", &[10u8; 32]);
    let mut agency_b = Authority::<Sig>::new("agency-b", &[20u8; 32]);
    let mut nodes: Vec<SimNode> = (0..N)
        .map(|i| {
            let root = if i < GS_B {
                agency_a.root_public_key()
            } else {
                agency_b.root_public_key()
            };
            let fielded = if i == LND_B { plan.t_enrol } else { 0 };
            SimNode::new(i, root, fielded)
        })
        .collect();
    let ids: Vec<NodeId> = nodes.iter().map(|n| n.identity.node_id()).collect();

    // Pre-deployment: each agency vouches its fielded assets; the lander is
    // vouched only when it lands.
    let a_bul: Vec<Bulletin> = (GS_A..GS_B)
        .map(|i| agency_a.announce_member(&ids[i], None, &[]))
        .collect();
    let b_bul: Vec<Bulletin> = (GS_B..LND_B)
        .map(|i| agency_b.announce_member(&ids[i], None, &[]))
        .collect();
    for i in GS_A..GS_B {
        nodes[i].add_bulletins(&a_bul);
    }
    for i in GS_B..LND_B {
        nodes[i].add_bulletins(&b_bul);
    }

    // ---- events by time ----------------------------------------------------
    // Peering: both authorities issue at the same moment, at their ground
    // stations. Enrolment: agency B vouches the lander at its ground station;
    // the lander itself is fielded carrying its own bulletin.
    let peer_ab = agency_a.announce_peer("agency-b", agency_b.root_public_key());
    let peer_ba = agency_b.announce_peer("agency-a", agency_a.root_public_key());
    let lnd_member = agency_b.announce_member(&ids[LND_B], None, &[]);

    // ---- traffic ------------------------------------------------------------
    // Every surface asset produces one bundle for the other collective every
    // `gen_every`, from when it is fielded until one lifetime before horizon.
    struct Job {
        src: usize,
        created: u64,
    }
    let mut jobs: Vec<Job> = Vec::new();
    for &src in &[ROV_A1, ROV_A2, ROV_B1, LND_B] {
        let mut t = nodes[src].fielded_at;
        while t + plan.lifetime <= plan.horizon {
            jobs.push(Job { src, created: t });
            t += plan.gen_every;
        }
    }
    jobs.sort_by_key(|j| (j.created, j.src));

    // ---- simulation: flood bulletins over the plan, record auth times -----
    // auth_at[(rx, tx)] = first minute at which rx can authorize tx.
    let mut auth_at: HashMap<(usize, usize), u64> = HashMap::new();
    let mut first_contact: HashMap<(usize, usize), u64> = HashMap::new();
    let mut peer_done = false;
    let mut enrol_done = false;

    let check_auth = |nodes: &Vec<SimNode>, t: u64, auth_at: &mut HashMap<(usize, usize), u64>| {
        for rx in 0..N {
            for tx in 0..N {
                if collective(rx) == collective(tx) || auth_at.contains_key(&(rx, tx)) {
                    continue;
                }
                if nodes[rx].can_authorize(&ids[tx]) {
                    auth_at.insert((rx, tx), t);
                }
            }
        }
    };
    check_auth(&nodes, 0, &mut auth_at);

    for c in &contacts {
        if !peer_done && c.t >= plan.t_peer {
            nodes[GS_A].add_bulletins(std::slice::from_ref(&peer_ab));
            nodes[GS_B].add_bulletins(std::slice::from_ref(&peer_ba));
            peer_done = true;
            check_auth(&nodes, plan.t_peer, &mut auth_at);
        }
        if !enrol_done && c.t >= plan.t_enrol {
            nodes[GS_B].add_bulletins(std::slice::from_ref(&lnd_member));
            nodes[LND_B].add_bulletins(&b_bul);
            nodes[LND_B].add_bulletins(std::slice::from_ref(&lnd_member));
            enrol_done = true;
            check_auth(&nodes, plan.t_enrol, &mut auth_at);
        }
        if c.t < nodes[c.a].fielded_at || c.t < nodes[c.b].fielded_at {
            continue;
        }
        let from_a = nodes[c.a].carried.clone();
        let from_b = nodes[c.b].carried.clone();
        nodes[c.a].add_bulletins(&from_b);
        nodes[c.b].add_bulletins(&from_a);
        if collective(c.a) != collective(c.b) {
            first_contact.entry((c.a, c.b)).or_insert(c.t);
            first_contact.entry((c.b, c.a)).or_insert(c.t);
        }
        // Bulletins apply at the end of the contact.
        check_auth(&nodes, c.t + c.dur, &mut auth_at);
    }

    // ---- score each bundle under each policy ---------------------------------
    // Cross-collective contacts per source, in time order.
    let mut cross_by_src: HashMap<usize, Vec<(u64, usize)>> = HashMap::new();
    for c in &cross {
        if c.a == GS_A && c.b == GS_B {
            continue; // ground-to-ground is not a route for in-situ traffic
        }
        cross_by_src.entry(c.a).or_default().push((c.t, c.b));
        cross_by_src.entry(c.b).or_default().push((c.t, c.a));
    }
    for v in cross_by_src.values_mut() {
        v.sort();
    }

    let mut blind = Stats::new();
    let mut bulletin_only = Stats::new();
    let mut self_auth = Stats::new();
    // Same three, restricted to bundles whose first cross-collective contact
    // fell inside a window (receiver not yet able to authorize the sender).
    let mut w_blind = Stats::new();
    let mut w_bulletin_only = Stats::new();
    let mut w_self_auth = Stats::new();
    let mut in_window_jobs = 0usize;
    let mut seen_pair: HashSet<(usize, usize)> = HashSet::new(); // for first-contact overhead, self-auth
    let mut seen_pair_bo: HashSet<(usize, usize)> = HashSet::new();
    let mut held_total: usize = 0;
    let mut deltas: Vec<f64> = Vec::new(); // hours saved per bundle, self-auth vs bulletin-only
    let mut worse = 0usize;
    let mut same = 0usize;

    let tx_cost = |seen: &mut HashSet<(usize, usize)>, rx: usize, tx: usize| -> u64 {
        if seen.insert((rx, tx)) {
            PAYLOAD_B + FIRST_CONTACT_OVERHEAD_B
        } else {
            PAYLOAD_B + STEADY_OVERHEAD_B
        }
    };

    // Real receivers for the self-auth path, one per node, exercising the
    // crate's accept_at/hold logic on real bundles.
    let mut real_rx: Vec<Receiver<Kem>> = (0..N)
        .map(|i| {
            let root = if i < GS_B {
                agency_a.root_public_key()
            } else {
                agency_b.root_public_key()
            };
            let (_, dk) = Kem::keygen(&seed_bytes(i, 4));
            Receiver::new(TrustStore::new(collective(i), root), dk)
        })
        .collect();

    for job in &jobs {
        let expiry = job.created + plan.lifetime;
        let empty = Vec::new();
        let opps = cross_by_src.get(&job.src).unwrap_or(&empty);
        let opps: Vec<&(u64, usize)> = opps
            .iter()
            .filter(|(t, _)| *t >= job.created && *t < expiry)
            .collect();

        // blind
        let o_blind = match opps.first() {
            Some(&&(t, _)) => Outcome {
                delivered_at: Some(t),
                transmissions: 1,
                bytes: PAYLOAD_B + STEADY_OVERHEAD_B,
            },
            None => Outcome {
                delivered_at: None,
                transmissions: 0,
                bytes: 0,
            },
        };

        // bulletin-only: re-offer at every cross contact until authorized.
        let mut o_bo = Outcome {
            delivered_at: None,
            transmissions: 0,
            bytes: 0,
        };
        for &&(t, rx) in &opps {
            o_bo.transmissions += 1;
            o_bo.bytes += tx_cost(&mut seen_pair_bo, rx, job.src);
            let ok = auth_at
                .get(&(rx, job.src))
                .map(|&ta| ta <= t)
                .unwrap_or(false);
            if ok {
                o_bo.delivered_at = Some(t);
                break;
            }
        }

        // self-auth: one transmission, held at the boundary until authorizable.
        let mut o_sa = Outcome {
            delivered_at: None,
            transmissions: 0,
            bytes: 0,
        };
        if let Some(&&(t, rx)) = opps.first() {
            let bundle = Sender::new(&nodes[job.src].identity, SourceName::SelfCertifying)
                .send_plain(b"survey-frame");
            let bound =
                verify_binding::<Sig>(&bundle).expect("binding must verify from the bundle alone");
            assert_eq!(bound, ids[job.src]);
            let verdict = real_rx[rx].accept_at::<Sig>(&bundle, t).expect("accept");
            assert!(verdict.binding_verified);
            o_sa.transmissions = 1;
            o_sa.bytes = tx_cost(&mut seen_pair, rx, job.src);
            let ta = auth_at.get(&(rx, job.src)).copied();
            match ta {
                Some(ta) if ta <= t => o_sa.delivered_at = Some(t),
                Some(ta) if ta < expiry => {
                    held_total += 1;
                    o_sa.delivered_at = Some(ta);
                }
                _ => {
                    held_total += 1;
                    o_sa.delivered_at = None;
                }
            }
        }

        blind.add(job.created, &o_blind);
        bulletin_only.add(job.created, &o_bo);
        self_auth.add(job.created, &o_sa);
        if let Some(&&(t, rx)) = opps.first() {
            let in_window = auth_at
                .get(&(rx, job.src))
                .map(|&ta| ta > t)
                .unwrap_or(true);
            if in_window {
                in_window_jobs += 1;
                w_blind.add(job.created, &o_blind);
                w_bulletin_only.add(job.created, &o_bo);
                w_self_auth.add(job.created, &o_sa);
            }
        }
        if let (Some(a), Some(b)) = (o_sa.delivered_at, o_bo.delivered_at) {
            let d = (b as f64 - a as f64) / HOUR as f64;
            deltas.push(d);
            if d < 0.0 {
                worse += 1;
            } else if d == 0.0 {
                same += 1;
            }
        }
    }

    // ---- windows per ordered pair --------------------------------------------
    println!("window per (receiver, sender) pair: first contact -> authorizable");
    let mut rows: Vec<(usize, usize, u64, Option<u64>)> = first_contact
        .iter()
        .map(|(&(rx, tx), &fc)| (rx, tx, fc, auth_at.get(&(rx, tx)).copied()))
        .filter(|(rx, tx, _, _)| !(*rx == GS_A && *tx == GS_B) && !(*rx == GS_B && *tx == GS_A))
        .collect();
    rows.sort();
    let mut windows: Vec<f64> = Vec::new();
    for (rx, tx, fc, ta) in &rows {
        let w = match ta {
            Some(ta) if ta > fc => {
                windows.push((ta - fc) as f64 / HOUR as f64);
                fmt_dur((ta - fc) as f64 / HOUR as f64)
            }
            Some(_) => "0 (authorizable at first contact)".to_string(),
            None => "never".to_string(),
        };
        let flood = match ta.as_ref() {
            Some(&ta) if *fc < plan.t_peer && ta >= plan.t_peer => format!(
                "   peering bulletin took {} to reach {}",
                fmt_dur((ta - plan.t_peer) as f64 / HOUR as f64),
                NAMES[*rx]
            ),
            Some(&ta)
                if *fc >= plan.t_enrol && (*rx == LND_B || *tx == LND_B) && ta >= plan.t_enrol =>
            {
                format!(
                    "   enrolment bulletin took {} to reach {}",
                    fmt_dur((ta - plan.t_enrol) as f64 / HOUR as f64),
                    NAMES[*rx]
                )
            }
            _ => String::new(),
        };
        println!(
            "  {:<7} <- {:<7} first contact day {:>5.1}   window {:<36}{}",
            NAMES[*rx],
            NAMES[*tx],
            *fc as f64 / DAY as f64,
            w,
            flood
        );
    }
    println!();

    // ---- summary ------------------------------------------------------------
    println!(
        "bundles: {} generated by 4 surface assets, one every {} h",
        jobs.len(),
        plan.gen_every / HOUR
    );
    println!();
    println!("  policy          delivered  expired   mean      median    p90       max       cross-link tx   bytes");
    for (name, s) in [
        ("blind", &blind),
        ("bulletin-only", &bulletin_only),
        ("self-auth", &self_auth),
    ] {
        println!(
            "  {:<15} {:>8}  {:>7}   {:>8}  {:>8}  {:>8}  {:>8}  {:>13}   {:>8.1} MiB",
            name,
            s.latencies.len(),
            s.expired,
            fmt_dur(s.mean()),
            fmt_dur(s.pct(0.5)),
            fmt_dur(s.pct(0.9)),
            fmt_dur(s.pct(1.0)),
            s.transmissions,
            s.bytes as f64 / (1024.0 * 1024.0)
        );
    }
    println!();
    println!(
        "same, restricted to the {} bundles whose first contact fell inside a window",
        in_window_jobs
    );
    println!();
    println!("  policy          delivered  expired   mean      median    p90       max       cross-link tx   bytes");
    for (name, s) in [
        ("blind", &w_blind),
        ("bulletin-only", &w_bulletin_only),
        ("self-auth", &w_self_auth),
    ] {
        println!(
            "  {:<15} {:>8}  {:>7}   {:>8}  {:>8}  {:>8}  {:>8}  {:>13}   {:>8.1} MiB",
            name,
            s.latencies.len(),
            s.expired,
            fmt_dur(s.mean()),
            fmt_dur(s.pct(0.5)),
            fmt_dur(s.pct(0.9)),
            fmt_dur(s.pct(1.0)),
            s.transmissions,
            s.bytes as f64 / (1024.0 * 1024.0)
        );
    }
    println!();
    let saved: Vec<f64> = deltas.iter().cloned().filter(|d| *d > 0.0).collect();
    println!("self-auth vs bulletin-only, per bundle delivered under both");
    println!(
        "  held in a window at the boundary ......... {}",
        held_total
    );
    println!(
        "  delivered earlier ........................ {}",
        saved.len()
    );
    println!("  delivered at the same time ............... {}", same);
    println!("  delivered later .......................... {}", worse);
    if !saved.is_empty() {
        let mut v = saved.clone();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let mean = v.iter().sum::<f64>() / v.len() as f64;
        println!(
            "  saving when earlier: mean {}  median {}  max {}",
            fmt_dur(mean),
            fmt_dur(v[v.len() / 2]),
            fmt_dur(*v.last().unwrap())
        );
    }
    println!(
        "  retransmissions avoided .................. {} ({:.1} MiB of cross-link capacity)",
        bulletin_only.transmissions - self_auth.transmissions,
        (bulletin_only.bytes as f64 - self_auth.bytes as f64) / (1024.0 * 1024.0)
    );
    if !windows.is_empty() {
        let mut w = windows.clone();
        w.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "  window across pairs that had one: min {}  median {}  max {}",
            fmt_dur(w[0]),
            fmt_dur(w[w.len() / 2]),
            fmt_dur(*w.last().unwrap())
        );
    }
    println!();

    // ---- latency CDF, pgfplots-ready ------------------------------------------
    // In-window bundles only: (days, fraction of in-window bundles delivered).
    // Expired bundles never reach 1.0, which is the point.
    println!(
        "latency CDF over the {} in-window bundles (days, fraction delivered), for pgfplots",
        in_window_jobs
    );
    for (name, s) in [
        ("blind", &w_blind),
        ("bulletin-only", &w_bulletin_only),
        ("self-auth", &w_self_auth),
    ] {
        let mut v = s.latencies.clone();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let n = in_window_jobs.max(1) as f64;
        let mut pts: BTreeMap<u64, f64> = BTreeMap::new();
        for (i, h) in v.iter().enumerate() {
            pts.insert((*h / 24.0 * 10.0).round() as u64, (i + 1) as f64 / n);
        }
        let mut line: Vec<String> = vec!["(0,0)".to_string()];
        line.extend(
            pts.iter()
                .map(|(d, f)| format!("({:.1},{:.3})", *d as f64 / 10.0, f)),
        );
        println!("  {}: {}", name, line.join(" "));
    }
    println!();
}

fn main() {
    let which = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "both".to_string());
    match which.as_str() {
        "lunar" => run(&lunar()),
        "mars" => run(&mars()),
        _ => {
            run(&lunar());
            run(&mars());
        }
    }
}
