# CCSDS DTN Reference Scenarios (vendored subset)

"DTN Reference Scenarios" by the Consultative Committee for Space Data
Systems (CCSDS), licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
Copyright © 2026 CCSDS.

- Source: <https://github.com/esa/ccsds-dtn-reference-scenarios>, branch `release`
- Commit: `5644a5fb751d6f6d2289e7acd77242850e28d2ef` (2026-08-13)
- Scenarios: `lunar-communication`, `mars-communication`, `low-earth-orbit`, all `v1.0.1`

## What is here

Unmodified copies of the machine-readable files only: `nodes.json`,
`planned_contacts.csv`, `actual_contacts.csv`, `traffic.json`, `policy.json`.
The description documents (`.adoc` / `.pdf`), images and `visibility.csv` are
not copied. Read the descriptions upstream; they define the topology,
the error model and the planning heuristics behind the contact files.

The files are byte-identical to upstream. Where the example has to interpret
or fill something, it does so in code and says so in its output (see below).
Nothing in this directory is covered by the crate's MIT / Apache-2.0 licence,
and the directory is excluded from the published crate.

## How `examples/refscenario.rs` reads them

- Contacts are directional; `contact_end = -1` means "to the end of the
  simulation", taken as the latest finite contact end (30 days in all three
  scenarios).
- `actual_contacts.csv` (planned contacts after the scenario's error model) is
  the default; `--contacts planned` switches to the plan.
- The organisational split into trust collectives is not in the machine-readable
  files. It is taken from the scenario descriptions ("five entities", colour
  coded) and hard-coded in the example, one table per scenario.
- In upstream `traffic.json` the last entry of both the lunar and the Mars
  scenario has no `ttl`. The example uses the TTL every other flow in that
  file uses (30 days) and prints a note.
- `policy.json` link restrictions are not applied (the lunar and Mars files
  contain none; LEO's apply to downlinks the example does not score).
- LEO has a single operator, so there is no trust boundary to measure. Its
  files are included for completeness; the example declines to run it.
- `data_rate` is not enforced (no queueing). It is used only to report the
  link time a signature costs on the first hop.

## Updating

Upstream versions coexist in versioned folders (`vMAJOR.MINOR.PATCH`); a patch
replaces the previous patch folder. To move to a new version, copy the same
five files into a new version folder, update the commit above, and point
`VERSION` in `examples/refscenario.rs` at it.
