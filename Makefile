.PHONY: test demo overhead coverage contactplan refscenario formal formal-lemmas bench pq nostd ud3tn fmt clippy clean

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

# Tamarin proofs (needs tamarin-prover and maude); logs in formal/results/.
# The V08 and CREATION_TIME variants are expected to FALSIFY the named lemmas.
TAMARIN = tamarin-prover
formal:
	@mkdir -p formal/results
	-cd formal && $(TAMARIN) --prove keylog.spthy > results/keylog.txt 2>&1
	-cd formal && $(TAMARIN) -D=V08 --prove=no_takeover_without_next_key \
	  --prove=v08_operational_key_takeover keylog.spthy > results/keylog_V08.txt 2>&1
	-cd formal && $(TAMARIN) --prove trust.spthy > results/trust.txt 2>&1
	-cd formal && $(TAMARIN) -D=V08 --prove=no_rollback trust.spthy > results/trust_V08.txt 2>&1
	-cd formal && $(TAMARIN) --prove promotion.spthy > results/promotion.txt 2>&1
	-cd formal && $(TAMARIN) -D=CREATION_TIME --prove=promotion_after_revocation_is_safe \
	  promotion.spthy > results/promotion_CREATION_TIME.txt 2>&1
	-cd formal && $(TAMARIN) --prove confidentiality.spthy > results/confidentiality.txt 2>&1
	@for f in formal/results/*.txt; do echo "== $$f"; sed -n '/summary of summaries/,$$p' $$f; done

# Same lemmas, one at a time with memory and time caps (safer on small VMs).
formal-lemmas:
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
