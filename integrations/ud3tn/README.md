# self-auth-dtn on uD3TN

[uD3TN](https://gitlab.com/d3tn/ud3tn) is a BPv7 agent for POSIX and
microcontrollers. It has no BPSec, so this integration carries the crate's
security blocks **inside the bundle payload** and talks to uD3TN as an
ordinary application over AAP 2.0.

```
 app ── ud3tn_node ──AAP 2.0──▶ uD3TN A ══MTCP══▶ uD3TN B ──AAP 2.0──▶ ud3tn_node ── app
        seal: self-auth block,                                     verify binding,
        BIB, optional BCB, as one                                  apply bulletins,
        CBOR payload (wire::encode_bundle)                         hold / promote / decrypt
```

## What is here

| Piece | Where | Status |
|---|---|---|
| Payload carriage of bundles and bulletins | `src/wire.rs` (`encode_bundle`, `encode_bulletin`, `adu_kind`) | no_std, tested (`tests/wire.rs`) |
| AAP 2.0 client (register, send, receive, keepalive) | `src/ud3tn/` (feature `ud3tn`) | tested against an in-process stand-in (`tests/ud3tn_aap2.rs`) and uD3TN |
| Field numbers | `src/ud3tn/fields.rs` | checked against uD3TN's `aap2.proto` |
| Endpoint program | `examples/ud3tn_node.rs` | lab provisioning only |
| Two-node harness | `run-local.sh` | passes, mock and post-quantum |
| Field-number generator / checker | `gen_fields.py` | |

## Verified

Run against uD3TN (cloned 2026-11-07) on two local nodes over MTCP, with mock
crypto and with ML-DSA-65 / ML-KEM-1024: identical results, the expected
summary line on both. `gen_fields.py --check` confirmed all 21 protobuf
constants against uD3TN's `aap2.proto`, and uD3TN accepts registration with
the full endpoint EID.

Payload sizes on the wire with the post-quantum suite (no rotations):

| ADU | Bytes |
|---|---|
| plain bundle, 27 B message | 8,692 |
| confidential bundle, 9 B message | 10,279 |

Both nodes ran on one host. Separate hosts, other convergence layers, larger
topologies (nse2) and interop with another BPv7 agent are not tested.

If a future uD3TN changes `aap2.proto`, `run-local.sh` stops at the field
check; regenerate with
`python3 integrations/ud3tn/gen_fields.py $UD3TN_DIR/components/aap2/aap2.proto > src/ud3tn/fields.rs`.

## Run it

```sh
git clone https://gitlab.com/d3tn/ud3tn.git ~/ud3tn
cd ~/ud3tn && git submodule update --init --recursive && make posix && make virtualenv
cd -   # back to self-auth-dtn
UD3TN_DIR=~/ud3tn ./integrations/ud3tn/run-local.sh          # mock crypto
UD3TN_DIR=~/ud3tn PQ=1 ./integrations/ud3tn/run-local.sh     # ML-DSA-65 / ML-KEM-1024
```

Expected last lines:

```
summary: bulletins=3 bundles=5 authorized=1 held=4 decrypted=1 refused=0
ok: ...
```

The five sends: two bundles before a's membership bulletin (held, then
promoted when it arrives), a confidential bundle for b (decrypted), a bundle
from c, whom nobody vouched for (binding holds, authorization does not), and
a bundle from a after its revocation (held).

By hand, in separate shells (uD3TN nodes and contact as in uD3TN's quick
start guide):

```sh
cargo build --release --features ud3tn --example ud3tn_node
N=target/release/examples/ud3tn_node
$N listen --socket ud3tn-b.aap2.socket --name b
$N send --socket ud3tn-a.aap2.socket --name a --to dtn://b.dtn/sad --bulletins last --count 3
$N send --socket ud3tn-a.aap2.socket --name a --to dtn://b.dtn/sad --to-name b --confidential
```

## What this integration does and does not show

It shows the protocol working through a real bundle agent and a real
convergence layer: identifiers bound offline at the receiver, bulletins
arriving in-band and in any order, retroactive promotion, revocation with
onset, and payload confidentiality, all with uD3TN unmodified.

It does not give BPSec semantics. Forwarders cannot check anything, because
the blocks are opaque payload. uD3TN's primary-block fields (source EID,
creation time) are outside what the signature covers, as they are in the
extension-block design: the self-certifying identifier inside the payload is
what is authenticated, and the source EID uD3TN reports is informational.
Checking at forwarders (the "any hop" policy of the reference scenarios)
needs the blocks as real extension blocks, which means BPSec in the agent (a security
context in uD3TN's C code calling this crate over FFI, or an agent that
already has BPSec).

`ud3tn_node` derives every key from public labels so that two terminals can
run the protocol without a provisioning step. Anyone can mint any of its
bulletins. It is a test fixture, not a deployment.
