.PHONY: test demo overhead coverage contactplan refscenario formal bench pq nostd ud3tn fmt clippy clean

test:
	cargo test --all-targets

demo:
	cargo run --example demo

overhead:
	cargo run --example overhead

coverage:
	cargo run --release --example coverage

contactplan:
	cargo run --release --example contactplan

refscenario:
	cargo run --release --example refscenario

# Every Tamarin lemma (needs tamarin-prover and maude), one at a time, capped
# in memory and time: whole-theory runs exhaust memory on small machines.
# The V08 and CREATION_TIME variants are expected to FALSIFY the named lemmas.
# Results: formal/results/lemmas/TABLE.txt.
formal:
	./formal/prove-lemmas.sh

bench:
	cargo run --release --example bench --features pq

pq:
	cargo test --all-targets --features pq

# no_std: the library and the suite without the std feature. The bare-metal
# build needs `rustup target add thumbv7em-none-eabihf`.
nostd:
	cargo test --all-targets --no-default-features --features mock
	cargo build --lib --release --no-default-features --features pq --target thumbv7em-none-eabihf

# Two real uD3TN nodes; see integrations/ud3tn/README.md. Needs UD3TN_DIR.
ud3tn:
	cargo test --all-targets --features ud3tn
	./integrations/ud3tn/run-local.sh

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets --features ud3tn

clean:
	cargo clean
