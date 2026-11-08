//! Contact-graph simulation measuring the pre-bulletin window: two
//! collectives, epidemic bulletin flooding, peering agreed mid-run.
//! Reports, per inter-collective encounter, how often binding was
//! available before authorization and by how much.
//!
//! Run with:  cargo run --release --example coverage

// Node-indexed loops read closer to the graph notation than iterators here.
#![allow(clippy::needless_range_loop)]

use self_auth_dtn::prelude::*;
use std::collections::{HashMap, HashSet};

type Sig = MockSig;

// ---------------------------------------------------------------------------
// Deterministic RNG (LCG), so runs are reproducible without a rand dependency.
// ---------------------------------------------------------------------------
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }
    fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) as u32
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u32() as usize) % n
    }
}

fn seed_bytes(i: usize, tag: u8) -> [u8; 32] {
    let mut s = [tag; 32];
    s[0] = i as u8;
    s[1] = (i >> 8) as u8;
    s
}

// ---------------------------------------------------------------------------
// A simulated node: identity, trust store, and the bulletins it carries.
// ---------------------------------------------------------------------------
struct SimNode {
    collective: String,
    identity: Identity<Sig>,
    trust: TrustStore,
    carried: Vec<Bulletin>,
    have: HashSet<(String, u64)>,
    applied: HashSet<(String, u64)>,
}

impl SimNode {
    fn new(collective: &str, root_key: &[u8], idx: usize) -> Self {
        let identity =
            Identity::<Sig>::incept(&seed_bytes(idx, 1), &seed_bytes(idx, 2), b"sim-node");
        SimNode {
            collective: collective.to_string(),
            identity,
            trust: TrustStore::new(collective, root_key),
            carried: Vec::new(),
            have: HashSet::new(),
            applied: HashSet::new(),
        }
    }

    /// Receive bulletins (from provisioning or from a contact), then try to
    /// apply everything pending until no further progress.
    fn add_bulletins(&mut self, incoming: &[Bulletin]) {
        for b in incoming {
            let key = (b.issuer.clone(), b.seq);
            if self.have.insert(key) {
                self.carried.push(b.clone());
            }
        }
        self.apply_pending();
    }

    fn apply_pending(&mut self) {
        loop {
            let mut progress = false;
            let mut pending: Vec<Bulletin> = self
                .carried
                .iter()
                .filter(|b| !self.applied.contains(&(b.issuer.clone(), b.seq)))
                .cloned()
                .collect();
            // Apply in (issuer, seq) order so sequence numbers are respected.
            pending.sort_by(|x, y| (x.issuer.as_str(), x.seq).cmp(&(y.issuer.as_str(), y.seq)));
            for b in pending {
                if self.trust.apply::<Sig>(&b).is_ok() {
                    self.applied.insert((b.issuer.clone(), b.seq));
                    progress = true;
                }
            }
            if !progress {
                break;
            }
        }
    }
}

fn bar(frac: f64, width: usize) -> String {
    let filled = (frac * width as f64).round() as usize;
    let mut s = String::new();
    for i in 0..width {
        s.push(if i < filled { '#' } else { '.' });
    }
    s
}

fn main() {
    // ---- parameters -------------------------------------------------------
    const N_PER: usize = 6; // nodes per collective
    const STEPS: usize = 120; // simulated time steps
    const CONTACTS_PER_STEP: usize = 2; // random pairwise contacts per step
    const T_PEER: usize = 30; // when the collectives agree to peer
    const SAMPLE_EVERY: usize = 6; // chart sampling interval

    let n_total = 2 * N_PER;
    let mut rng = Rng::new(0x5eed);

    // ---- collectives and nodes -------------------------------------------
    let mut agency_a = Authority::<Sig>::new("agency-a", &[10u8; 32]);
    let mut agency_b = Authority::<Sig>::new("agency-b", &[20u8; 32]);

    let mut nodes: Vec<SimNode> = Vec::with_capacity(n_total);
    for i in 0..N_PER {
        nodes.push(SimNode::new("agency-a", agency_a.root_public_key(), i));
    }
    for i in N_PER..n_total {
        nodes.push(SimNode::new("agency-b", agency_b.root_public_key(), i));
    }
    let node_ids: Vec<NodeId> = nodes.iter().map(|n| n.identity.node_id()).collect();

    // Pre-deployment provisioning: each collective issues membership bulletins
    // for its own nodes, and its nodes are fielded carrying them.
    let mut a_bulletins = Vec::new();
    for i in 0..N_PER {
        a_bulletins.push(agency_a.announce_member(&node_ids[i], None, &[]));
    }
    let mut b_bulletins = Vec::new();
    for i in N_PER..n_total {
        b_bulletins.push(agency_b.announce_member(&node_ids[i], None, &[]));
    }
    for i in 0..N_PER {
        nodes[i].add_bulletins(&a_bulletins);
    }
    for i in N_PER..n_total {
        nodes[i].add_bulletins(&b_bulletins);
    }

    // ---- bookkeeping -------------------------------------------------------
    // Ordered inter-collective pairs (receiver, sender).
    let mut first_contact: HashMap<(usize, usize), usize> = HashMap::new();
    let mut auth_at: HashMap<(usize, usize), usize> = HashMap::new();
    let mut window_bundles: HashMap<(usize, usize), usize> = HashMap::new();
    let mut encounters: usize = 0;
    let mut bindings_verified: usize = 0;
    let mut chart: Vec<(usize, f64, f64)> = Vec::new(); // (t, met_frac, auth_frac)

    let total_ordered_pairs = 2 * N_PER * N_PER;

    println!("contact-graph simulation");
    println!(
        "{} nodes in 2 collectives, {} steps, {} contacts/step, peering agreed at t={}",
        n_total, STEPS, CONTACTS_PER_STEP, T_PEER
    );
    println!();
    println!("legend: 'met'  = inter-collective (receiver, sender) pairs that have met");
    println!("        'auth' = pairs the receiver can authorize (peering + membership held)");
    println!();
    println!("  t    met   [fraction of all pairs]        auth  [fraction of all pairs]");

    // ---- simulation loop ---------------------------------------------------
    for t in 0..STEPS {
        // The peering event: each authority distributes the other's root key.
        // Injected at one node per collective; must flood from there.
        if t == T_PEER {
            let peer_ab = agency_a.announce_peer("agency-b", agency_b.root_public_key());
            let peer_ba = agency_b.announce_peer("agency-a", agency_a.root_public_key());
            nodes[0].add_bulletins(&[peer_ab]);
            nodes[N_PER].add_bulletins(&[peer_ba]);
        }

        for _ in 0..CONTACTS_PER_STEP {
            let i = rng.below(n_total);
            let mut j = rng.below(n_total);
            while j == i {
                j = rng.below(n_total);
            }

            // Epidemic exchange: full union of carried bulletins, both ways.
            let from_i = nodes[i].carried.clone();
            let from_j = nodes[j].carried.clone();
            nodes[i].add_bulletins(&from_j);
            nodes[j].add_bulletins(&from_i);

            // Inter-collective encounter: exercise the real verification path.
            if nodes[i].collective != nodes[j].collective {
                for (rx, tx) in [(i, j), (j, i)] {
                    let bundle = Sender::new(&nodes[tx].identity, SourceName::SelfCertifying)
                        .send_plain(b"survey-frame");
                    let bound = verify_binding::<Sig>(&bundle).expect("binding must verify");
                    assert_eq!(bound, node_ids[tx]);
                    encounters += 1;
                    bindings_verified += 1;

                    first_contact.entry((rx, tx)).or_insert(t);
                    if !auth_at.contains_key(&(rx, tx)) {
                        *window_bundles.entry((rx, tx)).or_insert(0) += 1;
                    }
                }
            }
        }

        // After this step's contacts and floods, check which met pairs have
        // become authorizable.
        for &(rx, tx) in first_contact.keys() {
            if !auth_at.contains_key(&(rx, tx))
                && nodes[rx]
                    .trust
                    .authorize(&node_ids[tx], &SourceName::SelfCertifying)
                    .is_ok()
            {
                auth_at.insert((rx, tx), t);
            }
        }

        if t % SAMPLE_EVERY == 0 || t == STEPS - 1 {
            let met_frac = first_contact.len() as f64 / total_ordered_pairs as f64;
            let auth_frac = auth_at.len() as f64 / total_ordered_pairs as f64;
            chart.push((t, met_frac, auth_frac));
        }
    }

    // ---- chart -------------------------------------------------------------
    for (t, met, auth) in &chart {
        let marker = if *t == T_PEER || (*t > T_PEER && *t < T_PEER + SAMPLE_EVERY) {
            " <- peering"
        } else {
            ""
        };
        println!(
            "{:>4}   {} {:>5.1}%   {} {:>5.1}%{}",
            t,
            bar(*met, 20),
            met * 100.0,
            bar(*auth, 20),
            auth * 100.0,
            marker
        );
    }

    // ---- summary -----------------------------------------------------------
    let met = first_contact.len();
    let authorized = auth_at.len();
    let retro: Vec<usize> = auth_at
        .iter()
        .filter_map(|(pair, &ta)| {
            let tf = first_contact[pair];
            if ta > tf {
                Some(ta - tf)
            } else {
                None
            }
        })
        .collect();
    let immediate = authorized - retro.len();
    let avg_window = if retro.is_empty() {
        0.0
    } else {
        retro.iter().sum::<usize>() as f64 / retro.len() as f64
    };
    let windowed_bundles: usize = window_bundles
        .iter()
        .filter(|(pair, _)| auth_at.contains_key(*pair))
        .map(|(_, &n)| n)
        .sum();

    println!();
    println!("summary");
    println!(
        "  inter-collective encounters ....................... {}",
        encounters
    );
    println!(
        "  bindings verified offline at those encounters ..... {} (100%)",
        bindings_verified
    );
    println!(
        "  ordered pairs that met ............................ {} of {}",
        met, total_ordered_pairs
    );
    println!(
        "  pairs authorizable by end of run .................. {} ({:.0}% of met)",
        authorized,
        100.0 * authorized as f64 / met.max(1) as f64
    );
    println!(
        "  of which authorized only retroactively ............ {} (avg window {:.1} steps)",
        retro.len(),
        avg_window
    );
    println!(
        "  of which authorizable already at first contact .... {}",
        immediate
    );
    println!(
        "  bundles exchanged inside windows, later authorized  {}",
        windowed_bundles
    );
    // ---- unordered view ----------------------------------------------------
    // Everything above, and the chart, counts ordered (receiver, sender)
    // pairs, because authorization is directional: A may be able to
    // authorize B before B can authorize A. If a slide says "N of 36
    // cross-collective pairs", it needs the unordered view below, and the
    // two views must never be mixed on one slide.
    let mut unordered: HashMap<(usize, usize), (usize, usize)> = HashMap::new(); // (dirs authorized, dirs retroactive)
    for (&(rx, tx), &tf) in first_contact.iter() {
        let key = (rx.min(tx), rx.max(tx));
        let e = unordered.entry(key).or_insert((0, 0));
        if let Some(&ta) = auth_at.get(&(rx, tx)) {
            e.0 += 1;
            if ta > tf {
                e.1 += 1;
            }
        }
    }
    let un_met = unordered.len();
    let un_retro_both = unordered.values().filter(|e| e.1 == 2).count();
    let un_retro_any = unordered.values().filter(|e| e.1 >= 1).count();
    let un_imm_both = unordered.values().filter(|e| e.0 == 2 && e.1 == 0).count();
    println!();
    println!("unordered view: {} cross-collective pairs", N_PER * N_PER);
    println!(
        "  pairs that met ................................... {}",
        un_met
    );
    println!(
        "  authorized only retroactively, in both directions  {}",
        un_retro_both
    );
    println!(
        "  authorized only retroactively, in at least one ... {}",
        un_retro_any
    );
    println!(
        "  authorizable at first contact, both directions ... {}",
        un_imm_both
    );

    println!();
    println!("reading the result");
    println!("  Binding held at every single encounter, including every one that");
    println!("  happened before the collectives had even agreed to peer. Those");
    println!(
        "  encounters produced {} bundles that a bulletin-only design",
        windowed_bundles
    );
    println!("  would have had no basis to accept, and that this design accumulated");
    println!("  under proven identifiers and authorized retroactively once the");
    println!("  peering and membership bulletins flooded far enough. The gap between");
    println!("  the two curves above is the window; self-auth is what makes the");
    println!("  traffic inside it usable.");
}
