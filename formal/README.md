# Formal model (Tamarin)

Symbolic (Dolev–Yao) models of self-auth-dtn 0.9 in the
[Tamarin prover](https://tamarin-prover.com). The attacker controls the
network, learns every key a compromise rule reveals, and can replay,
reorder, drop and forge anything it has the keys for. Signatures, hashes,
the KEM and the AEAD are ideal.

> **Status (2026-11-09): all results below hold.** Run on Tamarin 1.12.0 /
> Maude 3.5.1 with `prove-lemmas.sh`, one lemma at a time (3 GB, 1 thread):
> 37 rows, every one with its expected outcome, every `[reuse]` helper
> proved. Safety lemmas verify, the attack lemmas find their traces, and the
> three negative controls (`-D=V08` twice, `-D=CREATION_TIME`) are
> falsified, so the models do see the flaws that 0.9 fixes. Each lemma takes
> seconds; the slowest is about 100 s. Getting there took several
> restructurings, recorded under "If a proof does not terminate".

## Running

Tamarin 1.10 (or later) with Maude 3.x. Install via your package manager,
Homebrew or Nix (`nix profile install nixpkgs#tamarin-prover`).

```sh
make formal                                   # = ./formal/prove-lemmas.sh
MEM=3G THREADS=1 ./formal/prove-lemmas.sh keylog
ONLY=no_rollback ./formal/prove-lemmas.sh trust
```

### One lemma at a time, capped (recommended)

Running a whole theory lets one exploding lemma eat all memory and take the
machine down. `prove-lemmas.sh` runs each lemma separately with a heap cap
and a time limit, records verified / falsified / TIMEOUT / OUT-OF-MEM in
`results/lemmas/TABLE.txt`, and skips finished lemmas on the next run:

```sh
tmux new -s tamarin                    # survives SSH drops; detach: Ctrl-b d
./formal/prove-lemmas.sh promotion     # one theory
./formal/prove-lemmas.sh               # everything (MEM=5G TIME=30m THREADS=2)
```

On a VM without swap, add some first (once):

```sh
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
```

A single lemma by hand: `--prove=binding_no_splicing`. If one does not terminate,
open it in `tamarin-prover interactive .`, note where the search loops, and
bring that back; usually it needs a helper lemma or an oracle.

## Expected results

| file | lemma | property | result |
|---|---|---|---|
| keylog | `exec_accept_after_rotation`, `exec_accept_ipn` | sanity | verified (trace found) |
| keylog | `next_key_secrecy`, `op_key_secrecy`, `valid_ipn_from_inception`, `rx_after_first_sight`, `rx_log_monotone` | helpers | verified |
| keylog | `no_takeover_without_next_key` | 2 | verified |
| keylog | `binding_no_splicing` | 1 | verified |
| keylog | `rotation_ends_exposure` | 1b | verified |
| keylog | `ipn_pinned` | 6 | verified |
| keylog | `stale_log_cutoff`, `first_seen_no_branch_switch` | 3 | verified |
| keylog | `next_key_theft_takes_over`, `fork_wins_where_seen_first` | 10 | verified (trace found: the attack exists) |
| keylog `-D=V08` | `no_takeover_without_next_key` | 0.8 flaw | **falsified** (counterexample: forged head from the operational key alone) |
| trust | `exec_authorize_via_peer`, `exec_withdraw_then_regrant` | sanity | verified (trace found) |
| trust | `update_origin`, `grant_origin`, `withdraw_origin`, `member_origin` | helpers | verified |
| trust | `purge_on_withdrawal` | 8 (purge) | verified |
| trust | `authorization_sound` | 4 | verified |
| trust | `no_rollback` | 8 | verified |
| trust | `peer_root_compromise_authorizes_anyone` | 10 | verified (trace found) |
| trust `-D=V08` | `no_rollback` | 0.8 flaw | **falsified** |
| promotion | `exec_honest_promoted_after_revocation` | sanity | verified (trace found) |
| promotion | `promotion_after_revocation_is_safe` | 5 | verified |
| promotion | `promotion_before_revocation_is_exposed` | 10 | verified (trace found) |
| promotion `-D=CREATION_TIME` | `promotion_after_revocation_is_safe` | why receipt time | **falsified** |
| confidentiality | `exec_deliver_then_erase` | sanity | verified (trace found) |
| confidentiality | `no_reveal_after_erase` | helper | verified |
| confidentiality | `confidentiality` | 9 | verified |
| confidentiality | `forward_secrecy` | 7 | verified |
| confidentiality | `root_compromise_breaks_confidentiality` | 10 | verified (trace found) |

Any deviation from this table is a finding: either in the model or in the
design. The `V08` and `CREATION_TIME` variants must *fail*: they show the
model is sharp enough to find the flaws that 0.9 fixes.

## Properties

1. **Binding, no splicing.** A bundle accepted under an honest identifier,
   with a given claimed name and payload, was sent by the holder with exactly
   that name and payload, unless one of its keys was stolen before.
   Non-injective: DTN tolerates duplicates; replay belongs to another layer.
   **1b. Rotation ends the exposure** (`rotation_ends_exposure`): the stolen
   operational key must be the one of the very log head the bundle was
   accepted under, so a thief holding an earlier head's key gets nothing
   accepted under a later head.
2. **No takeover without the next key.** Every valid key-log head of an
   honest identifier was produced by its holder, unless a pre-committed next
   establishment key was stolen. Stealing the operational key never suffices.
   In 0.8 it did (`-D=V08`).
3. **Stale logs and forks.** A receiver's stored key log only grows. Once
   it has adopted a log it never accepts under a shorter one, and it never
   holds two different logs of the same length. Log length is modelled as a
   natural number, as the code keeps it.
4. **Authorization soundness, depth one.** A receiver authorizes an
   identifier only if its own root, or a collective its own root peered with
   directly, vouched for it, unless one of those roots was compromised.
5. **Safe promotion.** After a receiver applies a revocation, everything it
   promotes from that source was sent by the holder. Holds because promotion
   keys on the receiver's own receipt time; on the sender's timestamp it
   fails (`-D=CREATION_TIME`). **Assumes the stated onset is exact**: the
   authority's revocation names the actual compromise event (or states it
   unknown). An authority that estimates the onset late leaves the thief's
   bundles received in between promotable; the model does not show that gap.
6. **ipn pinning.** A bundle accepted under ipn number n, from an identity
   whose inception record carries an ipn commitment (`incept_with_ipn`),
   belongs to an identity that committed to n. Identities incepted with
   opaque metadata are not pinned; their entitlement rests on the bulletin.
   (The model gives every identity a commitment.)
7. **Forward secrecy.** After an epoch key is erased, a payload sealed to
   it can have leaked only through a reveal of that key before the erasure.
8. **No rollback.** After a withdrawal at sequence s, a receiver authorizes
   through that peer again only after a fresh grant with a higher sequence
   number; replaying the old grant changes nothing. In 0.8, withdrawal did
   not stop authorization at all (`-D=V08`). The purge is modelled too: a
   peer membership is recorded under the grant it arrived under and counts
   only while that grant is current (`purge_on_withdrawal`), so after a
   withdrawal and re-grant a membership has to arrive again. Replay of an
   old *membership* bulletin under the new grant is not refused in the model
   (membership freshness is not modelled; the code refuses it by sequence
   number), which only gives the attacker more.
9. **Confidentiality.** A confidential payload stays secret unless the
   destination's epoch key leaked or the root that vouched for its KEM key
   was compromised.
10. **Where it stops** (attacks Tamarin should find): theft of the
    pre-committed next key takes the identifier over; a receiver that meets a
    fork first keeps it; a compromised peer root authorizes anyone; a
    compromised root breaks confidentiality; before a revocation arrives,
    a thief's bundles are promoted like any others.

## Abstractions and what is not covered

- **Symbolic, not computational.** ML-DSA-65 and ML-KEM-1024 are ideal.
  Post-quantum security rests on their standard assumptions (EUF-CMA,
  IND-CCA), not on these proofs.
- **Design, not code.** The models follow the Rust (each file names the
  functions it models), but correspondence is argued, not mechanised.
- **Split per theory.** Each file models what its properties need: key logs
  abstract authorization, the trust model abstracts binding, and so on.
  Composition is argued, not proved.
- **Key logs as hash-chain heads.** A bundle names the head of the log it
  carries; receivers compare heads, which is what comparing logs event by
  event amounts to under collision resistance.
- **Not modelled:** `KeyReuse` checks (honest holders use fresh keys),
  bulletin expiry, member-record ownership between collectives, membership
  freshness and revocation in the trust model, link timing, eviction under
  `MAX_SOURCES`, and duplicity evidence beyond the receiver's refusal.
- **Time** in the promotion model is one global counter; real receivers
  need clocks that are monotone and close enough to the authority's notion
  of onset.

### Gaps found in review (closed in code)

- **Re-admission (property 5).** Lifting a revocation used to make the whole
  held history promotable again. The code now keeps [onset, re-admission) as
  a permanent suspect span. The model still has no re-admission at all, so
  property 5 is proved only for sources that stay revoked; the span rule is
  covered by `tests/promotion_gaps.rs`.
- **`Receiver::accept` without a clock (property 5).** Now stamps
  `UNKNOWN_RECEIPT_TIME`, excluded by every revocation, which matches the
  model's assumption that no unstamped bundle survives one.
- **Re-keying an epoch (property 7).** The replaced key is now destroyed. The
  model is stricter still (one key per epoch); a re-key in the code amounts to
  erasing the old key and adding a new one, which the model covers.

## If a proof does not terminate

- Expect "message derivation" wellformedness warnings on rules that match
  `sign(_, k)` with only `pk(k)` known. They are harmless here (`sign` is a
  free constructor); Tamarin continues.
- On a small VM start with `MEM=3G THREADS=1 TIME=20m`. Maude's memory is
  outside the heap cap; one thread halves the peak. Run a theory's
  `exec_*` and `[reuse]` helper lemmas first (they are listed first in
  `prove-lemmas.sh`), since a helper that does not prove is the usual
  reason a later lemma does not either.
- No theory uses numbers. The first versions used multiset counters (a
  clock, sequence numbers, log indices); AC unification on them ran out of
  memory (5 GB) even on sanity lemmas. Now time is event order
  (`promotion`), a sequence number is a fresh bulletin id ordered by when the
  authority issued it (`trust`, restriction `peer_fresh`), and a log
  position is its place in the hash chain (`keylog`: a child head hashes its
  parent).
- Subterm order for ancestry. `keylog`'s helper `rx_log_monotone` states
  that later adopted heads descend from earlier ones, with ancestry as the
  subterm order `P << H` (each head hashes its parent). A simpler helper,
  "each head is adopted once", does not close the property-3 lemmas: they
  need "a parent is never adopted after its child", and without the subterm
  order that means walking the adoption chain an unbounded number of steps.
- No linear state. Holder and receiver state (`!HolderState`, `!RxAdopted`),
  grants and memberships are persistent facts written once per transition
  and only read afterwards, with "current" restrictions (`holder_current`,
  `rx_current`, `peer_current`) in place of consume-and-recreate. A linear
  fact that every send, accept or authorization consumes and re-creates
  gives the backward search an unbounded chain to unroll; that is what kept
  the old `trust` lemmas from terminating (`keylog` had not been run yet).
- No free keys under signatures. `Rx_Apply_Grant` requires the granted key
  to be some collective's root. Without it the member bulletin in
  `Rx_Apply_Member_Peer` is checked under an unconstrained key, which the
  attacker can instantiate endlessly once a root leaks. The `*_origin`
  helpers then resolve every applied bulletin to one issue rule (or a root
  reveal) once, instead of at every use inside `peer_fresh`.
- Lemmas state only what the property needs. `purge_on_withdrawal` used to
  quantify over two grants and a membership application (four signed
  inputs); it is now one authorization implying one membership under the
  same grant, which with `peer_current` is the same property.
- Witness lemmas (exists-trace) get search bounds as extra conjuncts: one
  identity, one receiver, a bounded number of rotations, and for sanity
  lemmas only honest heads. A trace satisfying them is still a trace of the
  model, so nothing is weakened; without them `exec_accept_after_rotation`
  timed out exploring attacker-built inceptions and key-log chains.
- Inductive lemmas need a hypothesis strong enough for one step.
  `no_takeover_without_next_key` is stated over the whole validated state
  (head, operational key, commitment) rather than the head alone. With only
  "the parent head is honest", the prover had to rebuild the parent's
  commitment by walking back through the holder's history and ran out of
  memory; with the commitment in the hypothesis, the step is one hash
  comparison and one signature.
- A `[reuse]` helper "A implies there is a B" must not be applied to a rule
  that emits both A and B. The prover saturates: the new B-node emits
  another A, which needs another B. In `keylog` this made every lemma placed
  after `valid_ipn_from_inception` run out of memory within two minutes,
  trivial ones included; the fix was to stop `Valid_Inception` emitting
  `ValidN`. A tell-tale sign is a bounded run that dies in "Simplifier
  iteration N" with hundreds of identical actions on fresh nodes.
- Typed state patterns. Holder rules match `!HolderState(h(ix), ~op, ~nxt,
  h(hx), $n)`: identifiers and heads are hashes, keys are fresh. With untyped
  variables the prover could not rule out a secret key inside a published
  head without walking the holder's whole history.
- Ancestry by length, not by subterm. Property 3 first used the subterm
  order on heads (`P << H`) as "descends from"; attacker-chosen fields in
  forged events gave the subterm solver too much to explore and it ran out
  of memory. It now uses the log length as a natural number
  (`builtins: natural-numbers`), which is also what the code compares.
- If something still runs away, open it in `tamarin-prover interactive .`,
  autoprove with a bound of 10 to 20, and look at which goals pile up:
  `!KU(sign(...))` with a free key means a missing origin helper or a
  missing real-key premise; many copies of one restriction means it is
  quantifying over a pair that should be a single event.

## Map to the code

| theory | code |
|---|---|
| `keylog.spthy` | `src/identity.rs`, `src/keylog.rs` (`validate_chain`, `Identity::rotate`), `verify_binding` and `Receiver::accept_at` key-log handling in `src/verify.rs` |
| `trust.spthy` | `src/bulletin.rs`, `TrustStore::apply_at` (peering, withdrawal, membership) and `TrustStore::authorize` in `src/trust.rs` |
| `promotion.spthy` | `Receiver::accept_at` (receipt stamp), `Receiver::promotable_history`, revocation `effective_at` |
| `confidentiality.spthy` | `Sender::send_confidential`, `Receiver::erase_epochs_before`, `announce_member_epoch` |
