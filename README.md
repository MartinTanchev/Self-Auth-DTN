# 🛰️ self-auth-dtn

Self-authenticating node identifiers for the DTN Bundle Protocol (RFC 9171).
A node's ID is the hash of its signed key history, so a receiver can verify
**who sent a bundle from the bundle alone** — offline, no lookup, no handshake,
before any DTKA bulletin arrives.

## ⚡ Quick start

```sh
cargo test --all-targets       # full suite, one dependency (audited AEAD)
cargo run --example demo       # narrated end-to-end walkthrough
cargo run --release --example coverage   # contact-graph simulation
cargo run --release --example refscenario   # CCSDS lunar / Mars reference scenarios
cargo test --all-targets --features pq   # real ML-DSA-65 / ML-KEM-1024
cargo build --lib --no-default-features --features pq --target thumbv7em-none-eabihf   # no_std
UD3TN_DIR=~/ud3tn ./integrations/ud3tn/run-local.sh   # two real uD3TN nodes (integrations/ud3tn)
make formal                    # Tamarin proofs (formal/README.md)
```

## 🧠 The idea

- 🪪 **Binding, instantly:** `id = H(inception_record)`. The key material rides in the bundle; anyone can check it offline. Imposters are rejected on the spot.
- 📰 **Authorization, later:** DTKA bulletins (membership, peering, revocation) still say *"X is one of ours"* — whenever they arrive.
- ⏳ **The window:** between first contact and the bulletin, bundles accumulate under a proven identifier and are **authorized retroactively** the moment the bulletin lands. Nothing is discarded while you wait.

## 🔑 Rotation without losing yourself

KERI-style pre-committed rotation with split keys. **Establishment keys** control the identifier: each is pre-committed by hash, revealed by exactly one rotation event, signs that event, and is destroyed. **Operational keys** sign bundles: each rotation designates a fresh one. The identifier never moves.

- A thief with the **operational key** can impersonate you only until the next rotation or a revocation propagates, and cannot fork your key log: every past event was signed by an establishment key that no longer exists.
- A thief with the **pre-committed next key** can rotate the identifier. That is inherent to pre-rotation; keep it offline. Receivers keep the key log they **saw first** and refuse conflicting ones, recording the two events as `DuplicityEvidence` that anyone can check (`verify_duplicity`) and use to justify a revocation. Receivers that meet the fork first keep the fork until that revocation lands.

## 🤝 Federation

Peering is just another bulletin carrying the other collective's root key. Trust is pairwise and deliberately does **not** chain (A↔B and B↔C ≠ A→C). Revocation rides in ordinary bulletins too.

## 📦 Overhead (post-quantum, per bundle)

| charge | bytes |
|---|---:|
| BIB signature (steady state) | 3,309 |
| first contact, full identity material | 8,618 |
| per carried rotation event | 7,277 |
| KEM ciphertext (confidential bundles) | 1,568 |

Heavy vs classical (~40–50×), but harvest-now-decrypt-later makes PQ the right trade for links that live for decades.

## 🛰️ CCSDS reference scenarios

```sh
cargo run --release --example refscenario                    # lunar + Mars, both cases
cargo run --release --example refscenario -- mars --case federation --peer-day 3
```

`contactplan` measures the window on a synthetic, periodic plan. `refscenario` replays the **CCSDS DTN Reference Scenarios** ([esa/ccsds-dtn-reference-scenarios](https://github.com/esa/ccsds-dtn-reference-scenarios), vendored in [`scenarios/ccsds`](scenarios/ccsds/README.md), CC BY 4.0). They provide flight-dynamics contacts with the scenario error model applied, real link rates, and the scenarios' own traffic: 64 kB of science per second from every surface asset. Links are capacity-limited FIFO queues, so data refused during the window piles up at the source and has to drain through later passes.

Four policies: **blind** (insecure floor), **bulletin-only** (an oracle that never wastes a send), **self-auth, any hop** (the sender hands data to any foreign next hop, as on the STINT slides), and **self-auth, agreed hop** (the sender uses a hop only once its own trust store knows of the agreement). The agreement lands on day 10. Figures are mean latency to acceptance at the boundary for in-window blocks, using actual contacts:

| scenario, case | bulletin-only | self-auth, any hop | self-auth, agreed hop |
|---|---:|---:|---:|
| Mars, federation | 7.9 d | **5.1 d** | 7.9 d |
| Mars, cross-support, blue late | 7.7 d | **5.1 d** | 7.7 d |
| Mars, cross-support, orange late | 8.2 h | 5.5 d | 8.2 h |
| Lunar, federation | 5.2 d | 5.1 d | 5.2 d |
| Lunar, cross-support, blue late | 4.8 d | 5.3 d | 4.8 d |
| Lunar, cross-support, orange late | 2.8 h | 4.7 d | 2.8 h |

What it shows:

- **The gain needs a tight plan and an early sender.** On Mars, each rover's uplinks run at 74–80 % load in steady state. Under bulletin-only, ten days of refused science (peak ~61 GB per rover) never fully drain, and 464 of 4,320 blocks are still queued on day 30. With any-hop self-auth, everything is delivered and the rover's peak backlog stays at ~4 GB.
- **On a dense plan the window is cheap.** The lunar backlog clears in a single pass, so self-auth saves hours, not days.
- **On these topologies the relay is upstream of the asset**, so it learns of an agreement before the asset does, or at most hours later. A sender that waits until it knows (agreed hop) gains nothing over bulletin-only.
- **Which provider is late decides the outcome.** If it is an asset's only route (blue is rover 2's only provider on Mars), the case behaves like federation and self-auth wins. If an agreed provider is also in reach, handing data to the late one parks it there for days while bulletin-only routes around it. Holding complements routing that prefers authorized hops; it does not replace it. Which provider is late is set with `--late`.
- **Holding moves storage, it does not remove it.** Under any-hop self-auth, relays hold up to ~59 GB awaiting authorization. Relay storage and the relay-to-ground leg (4 Mbps on Mars) are not modelled. End-to-end figures need a DTN simulator or emulator, e.g. [esa/nse2](https://github.com/esa/nse2) with a bundle agent.
- **Per-bundle signatures are cheap on science and expensive on commands:** 5 % on a 64 kB science bundle, 6.5× the payload on a 512 B telecommand.

Checks: a hand-computed toy case reproduces the queue model's delivery times, holds and peak backlog. A recount from the raw CSV confirms the Mars backlog: rover 1 can send 155 GB over days 10–30 against 179 GB queued and generated. Results are stable under `--contacts planned` and `--sample-min 10`. `--peer-day 3` shrinks the Mars gap to 2.2 d → 1.7 d.

## 🆕 0.9.0 (breaking)

- **Fix: identity takeover after a rotation.** Up to 0.8 the key revealed by a rotation event also signed bundles, and receivers compared key logs by length only. A thief holding that key could sign an alternative version of the rotation event committing to its own successor, extend the fork past the real log, take the identifier over (authorization included, since it is keyed on the identifier), and lock the holder out as stale. Reproduced against 0.8 and kept as a regression test (`tests/fork_takeover.rs`).
- **Split keys.** `KeyEvent` gains `operational_public_key`; the revealed establishment key signs only its event and is destroyed. `Identity::rotate(operational_seed, next_seed)`. Logs where an operational key equals an establishment key are refused (`VerifyError::KeyReuse`). Each carried rotation event grows by one public key (5,325 → 7,277 B with ML-DSA-65); the per-bundle signature is unchanged.
- **First-seen key logs and duplicity evidence.** Receivers store the key log they first saw per identifier instead of its length. A conflicting log is refused (`VerifyError::Duplicity`) and the two events are kept (`Receiver::duplicity`, `verify_duplicity`). A strict prefix is still `StaleKeyLog`.
- **Fix: withdrawal now ends a peer's memberships.** Up to 0.8, members vouched by a peer stayed authorized (and kept supplying KEM keys) after the peering was withdrawn; only the peer's future bulletins were refused. Withdrawal, and a re-grant under a different root, now purge the records that collective vouched; sequence state is kept, so the old bulletins cannot be replayed back in. A grant naming the receiver's own collective is refused, as a withdrawal of it already was: no bulletin replaces the own root.
- **Fix: re-admission no longer restores a thief's bundles.** Lifting a revocation by re-admission used to make the whole held history promotable again. The span from the stated onset to the re-admission now stays suspect for good (`TrustStore::suspect_spans`); apply bulletins with `Receiver::apply_bulletin_at` to close the span at the real time, otherwise it stays open.
- **Fix: `Receiver::accept` without a clock fails safe.** It stamped receipt time 0, so any revocation with a stated onset promoted everything. It now stamps `UNKNOWN_RECEIPT_TIME`, which every revocation and suspect span excludes.
- **Fix: re-keying an epoch destroys the replaced key.** `add_epoch_key` used to drop it without `KemScheme::destroy`.
- **Fix: resource bounds.** The wire decoder reserved memory for any declared rotation count before reading it (a few bytes could ask for gigabytes); key logs were unbounded (each event is a signature check per bundle), and since first-seen logs receivers kept whole logs per identifier. Logs are now capped at `MAX_KEY_EVENTS` (64; `VerifyError::KeyLogTooLong`, refused in the decoder before allocating), and receivers keep only a log's length and newest event.
- **`no_std` + `alloc`.** The library builds without `std` (`--no-default-features`), for BPAs on bare metal or an RTOS; checked by building for `thumbv7em-none-eabihf` with the post-quantum backends. The new `std` feature (on by default) only enables hedged ML-DSA signing with OS randomness; without it ML-DSA signs in the FIPS 204 deterministic mode. Dependencies are pulled without default features (one ML-DSA and one ML-KEM parameter set, no OS RNG). Internal maps are `BTreeMap`, so receiver state no longer depends on a hash seed. A heap allocator is still required.
- **Confidential bundles bound to their source.** The BCB's AEAD associated data was only the KEM ciphertext, so an attacker could lift a captured BCB into a bundle under its own identifier, re-sign it, and the destination would decrypt it as the attacker's (found by external review). The associated data is now a domain label, source identifier, KEM epoch and ciphertext (`verify::bcb_aad`). Bundles sealed by 0.9 pre-releases no longer open.
- **Membership expiry is enforced.** `announce_member_until` used to be checked only on arrival; the record kept no expiry, so the member stayed authorized forever. `MemberRecord::expires_at` now holds it, `TrustStore::authorize_at` / `Receiver::authorization_at` refuse a lapsed member (`TrustError::MembershipExpired`), and `Receiver::accept_at` uses it. Clockless `authorize` does not check expiry, like clockless `apply`.
- **Hygiene.** Dead HMAC and constant-time-compare code removed; CI now blocks on fmt and clippy and builds no_std (thumbv7em) and the uD3TN client; `Cargo.lock` is committed.
- **uD3TN integration (payload carriage).** `wire::encode_bundle` / `encode_bulletin` carry a whole secured bundle or a bulletin as one CBOR payload, for agents without BPSec. Feature `ud3tn` adds a dependency-free AAP 2.0 client (`src/ud3tn/`) and `examples/ud3tn_node.rs`; `integrations/ud3tn/run-local.sh` runs two real uD3TN nodes; it passes with mock and post-quantum crypto (a post-quantum plain bundle is 8,692 B on the wire). See `integrations/ud3tn/README.md`.
- **Wire version 2.** Rotation events carry six fields; version 1 is refused.
- **Formal model.** `formal/` holds Tamarin theories for binding, rotation, first-seen logs, authorization, rollback, promotion and confidentiality, with `-D=V08` variants in which the two fixed flaws reappear as attacks. See `formal/README.md`.

## 🆕 0.8.0

- **Member records are owned.** A membership record belongs to the collective that vouched it: a peer collective can neither overwrite another collective's record (KEM-key substitution → confidentiality MITM) nor suppress its members by foreign revocation. Pre-emptive revocation of an unknown identifier stands until a collective actually vouches for it.
- **Peering can be withdrawn.** A peering bulletin with an empty root key removes the peer's root; ordering against the grant is the usual per-subject sequence. `Authority::withdraw_peer`.
- **Forward secrecy is implemented.** Membership bulletins announce per-epoch KEM keys (`announce_member_epoch`); senders encapsulate under the newest epoch; `Receiver::erase_epochs_before` destroys expired decapsulation keys. A bundle sealed to an erased epoch is permanently unreadable — by test — which is also the bound: erase no earlier than one max bundle lifetime after an epoch closes.

## 🆕 0.7.0

- **Per-subject bulletin freshness.** Replay protection is now tracked per (issuer, subject) instead of per issuer, so a legitimately delayed bulletin about node A is no longer refused because newer news about node B arrived first. Bulletins reorder in a DTN; "valid however late it arrives" now survives that.
- **Receipt-time promotion.** `Receiver::accept_at` stamps every accumulated bundle with the receiver's own clock, and `promotable_history` promotes only bundles received before a revocation's `effective_at` (a stolen key can backdate a creation timestamp, not your clock). A revocation with unknown onset voids the history, conservatively.
- **Pinned watermarks.** Identifier floods can no longer evict a member's rotation watermark and reopen the stale-key-log window against it: eviction only claims sources the trust store does not recognise.
- **Committed ipn numbers.** `Identity::incept_with_ipn` commits the claimed node number inside the inception record, making the claim non-equivocable already in the window. Entitlement stays with the bulletin.
- **ML-KEM-1024.** The `pq` KEM backend moves from ML-KEM-768 to ML-KEM-1024, the parameter set CNSA 2.0 approves (ciphertext 1,568 B).
- **Re-admission.** A membership bulletin issued after a revocation (same issuer, higher seq) lifts it.

## ⚠️ Honest limits

- 🔑 Theft of the **pre-committed next key** still yields the identifier at every receiver that meets the thief's fork first. First-seen detection and evidence make it visible and revocable, not impossible. Keep next keys offline.

- 🧾 The BIB covers the source identifier, the claimed name and the payload digest only: no destination, creation time, sequence number or algorithm suite. There is no replay protection (DTN tolerates duplicates), and the suite is unauthenticated, which is safe only because a receiver runs one backend. A mixed-suite receiver would need the suite under the signature.
- 🤝 A collective cannot distrust a single member of a peer collective: a peer's records are the peer's (`MemberOfAnotherCollective`). The only lever is withdrawing the whole peering.
- 🔐 Confidentiality is **not** self-contained: encrypting *to* a node still needs its KEM key from a bulletin (`SendError::NoDestinationKey`).
- 📦 On uD3TN the blocks travel inside the payload, so forwarders cannot check them; checking at any hop needs BPSec in the agent.
- 🧮 Without `std`, ML-DSA signs deterministically (FIPS 204 permits it), which is more exposed to fault and side-channel attacks than hedged signing. Targets with a hardware RNG should add a hedged path.
- 🧪 Default backends are insecure mocks, feature-gated out of production builds (`--no-default-features --features pq`).
- 🔍 The AEAD is RustCrypto's `chacha20poly1305` (NCC Group audited), pinned in-tree to the RFC 8439 vector. The FIPS-204/203 crates are NIST-vector-tested but not independently audited; the in-crate SHA-256 hashes public material only.

## 📜 License

MIT or Apache-2.0, at your option.
