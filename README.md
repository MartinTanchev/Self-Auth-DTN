# self-auth-dtn

Self-authenticating node identifiers for the DTN Bundle Protocol (RFC 9171).
A node's identifier is the hash of its signed key history, so a receiver can
tell **who sent a bundle from the bundle alone**: offline, with no lookup and
no handshake, before any key bulletin has arrived.

Research prototype, version 0.9.0. Post-quantum (ML-DSA-65, ML-KEM-1024,
feature `pq`), `no_std`, tested against a real bundle agent (uD3TN), with
Tamarin models of its security properties.

## Quick start

```sh
cargo test --all-targets                      # test suite, mock crypto
cargo test --all-targets --features pq        # same suite, ML-DSA-65 / ML-KEM-1024
cargo run --example demo                      # narrated end-to-end walkthrough
cargo run --release --example refscenario     # CCSDS lunar and Mars reference scenarios
cargo build --lib --no-default-features --features pq --target thumbv7em-none-eabihf   # bare metal
UD3TN_DIR=~/ud3tn ./integrations/ud3tn/run-local.sh   # two real uD3TN nodes
./formal/prove-lemmas.sh                      # Tamarin proofs, one lemma at a time
./scripts/run-all.sh                          # everything above, logged
```

## How it works

**Binding now, authorization later.** `id = H(inception_record)`. The key
material travels with the bundle, so anyone can check offline that the
bundle was signed by the holder of that identifier, and imposters are refused
on the spot. Whether the identifier *belongs* (is a member of a trusted
collective) still comes from DTKA bulletins, whenever they arrive. In
between, bundles accumulate under a proven identifier and are authorized
retroactively when the bulletin lands, instead of being discarded.

**Rotation without changing identity.** KERI-style pre-committed rotation
with split keys. *Establishment keys* control the identifier: each is
committed by hash in advance, revealed by exactly one rotation event, signs
that event, and is destroyed. *Operational keys* sign bundles; each rotation
designates a fresh one. The identifier never changes.

- A thief with the operational key can impersonate the node only until its
  next rotation or a revocation, and cannot fork its key log: every past
  event was signed by an establishment key that no longer exists.
- A thief with the pre-committed next key can rotate the identifier; that is
  inherent to pre-rotation, so next keys stay offline. Receivers keep the
  key log they saw first, refuse a conflicting one, and keep both events as
  `DuplicityEvidence` that anyone can verify and use to justify a
  revocation.

**Federation.** Peering is another bulletin carrying the other collective's
root key. Trust is pairwise and does not chain: A trusts B and B trusts C
does not mean A trusts C. A membership record belongs to the collective that
vouched for it; a peer can neither overwrite nor revoke another collective's
members. Withdrawing a peering removes the members that peer vouched for.

**Revocation and promotion.** Each held bundle is stamped with the
receiver's own receipt time. A revocation states when the compromise began,
and only bundles received before that onset are promoted. A stolen key can
backdate a bundle's creation time, not the receiver's clock. An unknown onset
promotes nothing.

**Confidentiality.** Optional per-bundle encryption: ML-KEM-1024
encapsulation to the destination's announced key, then ChaCha20-Poly1305 with
the source identifier, epoch and KEM ciphertext as associated data. KEM keys
rotate by epoch, and erasing an epoch's key makes everything sealed to it
permanently unreadable (forward secrecy).

**Freshness.** Bulletin replay protection is per issuer and subject, so a
delayed bulletin about one node is not refused because newer news about
another arrived first.

## Engineering

- **`no_std` + `alloc`.** The library builds for bare-metal targets
  (checked on `thumbv7em-none-eabihf` with the post-quantum backends). The
  `std` feature only adds hedged ML-DSA signing from OS randomness.
- **One `unsafe` block** in the whole crate (volatile zeroing of secrets),
  `#![deny(unsafe_code)]` everywhere else.
- **Pluggable crypto.** `SignatureScheme` and `KemScheme` traits, with real
  backends (`fips204`, `fips203`, RustCrypto `chacha20poly1305`) and
  deterministic mocks for tests; mocks are feature-gated out of production
  builds.
- **Hostile-input decoding.** A hand-written CBOR subset (RFC 8949) for the
  wire format. Lengths and counts are checked before anything is allocated,
  trailing bytes and unknown tags are refused, and key logs are capped at 64
  events.
- **Dependency-free AAP 2.0 client** for uD3TN (feature `ud3tn`), with a
  hand-written protobuf subset whose field numbers are checked against
  uD3TN's `aap2.proto` by `integrations/ud3tn/gen_fields.py`.
- **Typed errors** throughout. The library panics only on documented
  caller misuse (`Identity::rotate` past the 64-event cap, or with reused
  seeds) and where the crypto backend cannot fail.
- **CI:** rustfmt and clippy (`-D warnings`), tests with mock and real
  crypto, the `no_std` bare-metal build, and the uD3TN client.

## Verification

- **Tests.** 94 tests (`--features ud3tn`): one regression test per fixed
  flaw, property-style decoder fuzzing, resource bounds, and end-to-end
  scenarios (rotation, compromise, federation, revocation, re-admission,
  confidentiality). The suite passes with mock and post-quantum backends.
- **Interop.** Two uD3TN nodes over MTCP, one scripted exchange (held
  bundles, promotion, decryption, an unvouched sender, revocation), passing
  with mock and post-quantum crypto. See
  [`integrations/ud3tn`](integrations/ud3tn/README.md).
- **Formal models.** Tamarin theories for binding, rotation, first-seen
  logs, authorization, rollback, promotion and confidentiality, each with a
  negative control that reintroduces an old flaw and must be falsified.
  `confidentiality`, `promotion` and `trust`: every lemma verified, negative
  controls falsified. `keylog`: in progress. See
  [`formal/README.md`](formal/README.md).

## Overhead (post-quantum, per bundle)

| item | bytes |
|---|---:|
| BIB signature (steady state) | 3,309 |
| first contact, full identity material | 8,618 |
| per carried rotation event | 7,277 |
| KEM ciphertext (confidential bundles) | 1,568 |

About 40 to 50 times a classical scheme. For links that live for decades,
harvest-now-decrypt-later makes post-quantum the right trade.

## CCSDS reference scenarios

```sh
cargo run --release --example refscenario                    # lunar + Mars, both cases
cargo run --release --example refscenario -- mars --case federation --peer-day 3
```

`refscenario` replays the **CCSDS DTN Reference Scenarios**
([esa/ccsds-dtn-reference-scenarios](https://github.com/esa/ccsds-dtn-reference-scenarios),
vendored in [`scenarios/ccsds`](scenarios/ccsds/README.md), CC BY 4.0):
flight-dynamics contacts with the scenario error model applied, real link
rates, and the scenarios' own traffic of 64 kB of science per second from
every surface asset. Links are capacity-limited FIFO queues, so data refused
during the window piles up at the source and has to drain through later
passes. (`contactplan` measures the window on a synthetic, periodic plan.)

Four policies: **blind** (insecure floor), **bulletin-only** (an oracle that
never wastes a send), **self-auth, any hop** (the sender hands data to any
foreign next hop), and **self-auth, agreed hop** (the sender uses a hop only
once its own trust store knows of the agreement). The agreement lands on day
10. Mean latency to acceptance at the boundary for in-window blocks, actual
contacts:

| scenario, case | bulletin-only | self-auth, any hop | self-auth, agreed hop |
|---|---:|---:|---:|
| Mars, federation | 7.9 d | **5.1 d** | 7.9 d |
| Mars, cross-support, blue late | 7.7 d | **5.1 d** | 7.7 d |
| Mars, cross-support, orange late | 8.2 h | 5.5 d | 8.2 h |
| Lunar, federation | 5.2 d | 5.1 d | 5.2 d |
| Lunar, cross-support, blue late | 4.8 d | 5.3 d | 4.8 d |
| Lunar, cross-support, orange late | 2.8 h | 4.7 d | 2.8 h |

What it shows:

- **The gain needs a tight plan and an early sender.** On Mars, each rover's
  uplinks run at 74 to 80% load. Under bulletin-only, ten days of refused
  science (peak about 61 GB per rover) never fully drain, and 464 of 4,320
  blocks are still queued on day 30. With any-hop self-auth everything is
  delivered and the rover's peak backlog stays near 4 GB.
- **On a dense plan the window is cheap.** The lunar backlog clears in one
  pass, so self-auth saves hours, not days.
- **The relay is upstream of the asset** on these topologies, so it learns of
  an agreement first. A sender that waits until it knows (agreed hop) gains
  nothing over bulletin-only.
- **Which provider is late decides the outcome.** If it is an asset's only
  route, self-auth wins. If an agreed provider is also in reach, handing
  data to the late one parks it there for days while bulletin-only routes
  around it. Holding complements routing that prefers authorized hops; it
  does not replace it (`--late` selects the late provider).
- **Holding moves storage, it does not remove it.** Under any-hop self-auth,
  relays hold up to about 59 GB awaiting authorization. Relay storage and the
  relay-to-ground leg are not modelled; end-to-end figures need a DTN
  emulator such as [esa/nse2](https://github.com/esa/nse2).
- **Signatures are cheap on science and expensive on commands:** 5% on a
  64 kB science bundle, 6.5 times the payload on a 512 B telecommand.

Checks: a hand-computed toy case reproduces the queue model's delivery
times, holds and peak backlog; a recount from the raw CSV confirms the Mars
backlog; results are stable under `--contacts planned` and
`--sample-min 10`; `--peer-day 3` shrinks the Mars gap from 2.2 d to 1.7 d.

## Notable fixes in 0.9

Found while building the formal models or by review, each with a
regression test:

- **Identity takeover after rotation.** Up to 0.8, the key revealed by a
  rotation also signed bundles, and receivers compared key logs by length. A
  thief with that key could fork the log and take the identifier over. Fixed
  by the split establishment/operational keys and first-seen logs
  (`tests/fork_takeover.rs`).
- **Authorship confusion on confidential bundles.** The AEAD bound only the
  KEM ciphertext, so a captured payload could be re-signed under another
  identifier and would decrypt as that sender's. The source identifier is
  now associated data (`verify::bcb_aad`).
- **Withdrawal, re-admission, expiry.** Withdrawing a peering now removes its
  members; re-admission no longer re-promotes bundles from the compromise
  window; membership expiry is enforced, not just checked on arrival.
- **Resource bounds.** The decoder no longer reserves memory for a declared
  count before reading it, and receivers keep only a log's length and newest
  event.

The wire format is version 2; version 1 logs are refused. Earlier history is
in the git log.

## Limitations

- Theft of the **pre-committed next key** still yields the identifier at
  every receiver that meets the thief's fork first. First-seen logs and
  duplicity evidence make it visible and revocable, not impossible.
- The BIB covers the source identifier, claimed name and payload digest
  only: no destination, creation time, sequence number or algorithm suite.
  There is no replay protection (DTN tolerates duplicates), and the suite is
  unauthenticated, which is safe only because a receiver runs one backend.
- A collective cannot distrust a single member of a peer collective; the
  only lever is withdrawing the whole peering.
- Sending confidentially still needs the destination's KEM key from a
  bulletin.
- On uD3TN the security blocks travel inside the payload, so forwarders
  cannot check them; checking at every hop needs BPSec in the agent.
- Without `std`, ML-DSA signs deterministically (FIPS 204 permits it), which
  is more exposed to fault and side-channel attacks than hedged signing.
- The default backends are insecure mocks, for tests; production builds use
  `--no-default-features --features pq`.
- The AEAD is RustCrypto's `chacha20poly1305` (audited by NCC Group). The
  FIPS 204/203 crates pass NIST vectors but are not independently audited.
  The in-crate SHA-256 hashes public material only.

## License

MIT or Apache-2.0, at your option.
