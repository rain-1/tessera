# Developer and CI entry points. `make help` lists targets.
# Rust tools are expected in ~/.cargo/bin (rustup default).
export PATH := $(HOME)/.cargo/bin:$(PATH)

CARGO      ?= cargo
NIGHTLY    ?= nightly
FUZZ_SECS  ?= 30
FUZZ_TARGETS = protocol_decode_client protocol_decode_server frame_reader \
               approval_grant_request approval_enrollment journal_recover \
               core_state_decode core_step

.PHONY: help build release test lint fmt clippy models tlc verus fuzz-build \
        fuzz-smoke fuzz-seeds adversarial deny audit sbom repro demo ci

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

build: ## Debug build of every workspace binary
	$(CARGO) build --workspace --locked --bins

release: ## Reproducible release build (see docs/release.md)
	scripts/release-build.sh

test: ## cargo test --workspace (sandbox tests SKIP loudly without userns/cgroup)
	$(CARGO) test --workspace --locked

lint: fmt clippy ## rustfmt check + clippy -D warnings

fmt:
	$(CARGO) fmt --all --check

clippy:
	$(CARGO) clippy --workspace --all-targets --locked -- -D warnings

models: ## Explicit-state Python model checker (models/)
	python3 -I models/dispatch_model.py

tlc: ## TLC on models/Dispatch.tla (downloads a pinned tla2tools.jar; needs java)
	models/run_tlc.sh

verus: ## Verus proofs (needs proofs/run_verus.sh from the verification branch)
	@if [ -x proofs/run_verus.sh ]; then proofs/run_verus.sh; \
	 else echo "proofs/run_verus.sh not present; nothing to verify" >&2; exit 2; fi
	cd proofs && $(CARGO) test --locked # differential test: mirror vs production core

fuzz-build: ## Build all cargo-fuzz targets (nightly + cargo-fuzz)
	cd fuzz && $(CARGO) +$(NIGHTLY) fuzz build

fuzz-seeds: ## Regenerate structured seed inputs in fuzz/seeds/
	cd fuzz && $(CARGO) +$(NIGHTLY) run -q --example gen_seeds

fuzz-smoke: fuzz-build ## Run every fuzz target for FUZZ_SECS seconds (default 30)
	@cd fuzz; rc=0; for t in $(FUZZ_TARGETS); do \
	  mkdir -p corpus/$$t seeds/$$t; echo "== $$t ($(FUZZ_SECS)s)"; \
	  if $(CARGO) +$(NIGHTLY) fuzz run $$t corpus/$$t seeds/$$t -- \
	      -max_total_time=$(FUZZ_SECS) -rss_limit_mb=2048 -timeout=10 > $$t.log 2>&1; \
	  then grep -E '^Done' $$t.log; \
	  else rc=1; tail -40 $$t.log; echo "CRASH in $$t: reproducer under fuzz/artifacts/$$t/"; fi; \
	done; exit $$rc

adversarial: ## Hostile-shell corpus against the real launcher
	tests/adversarial/run.sh

deny: ## cargo-deny: advisories, licenses, bans, sources
	$(CARGO) deny check

audit: ## cargo-audit against the RustSec database
	$(CARGO) audit

sbom: ## Regenerate CycloneDX SBOMs in docs/sbom/
	scripts/sbom.sh

repro: ## Build release binaries twice from two checkouts and compare
	scripts/repro-check.sh

demo: ## tesserad + sandbox + software-key approval walkthrough
	scripts/demo.sh

ci: lint test models deny ## The subset of CI that needs no extra tooling
