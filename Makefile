.PHONY: check validate verify plan conformance conformance-cli conformance-go examples vet differential embed-vocab parity mutation race lint cover tidy export-check repro-check

# the gate for every change: all suites, both implementations, vet
check: vet validate conformance conformance-cli conformance-go examples
	@echo "all gates passed"

# every shipped example must still work — verify AND plan, plus the README's
# converge loop. Runs here so the export's standalone `make check` proves the
# examples in the PUBLIC tree before anything is pushed there.
examples:
	@cd go && go build -o ../bin/groundhold-go ./cmd/groundhold
	@./examples/check.sh

vet:
	@cd go && f=$$(gofmt -l .); if [ -n "$$f" ]; then echo "gofmt: unformatted files:"; echo "$$f"; exit 1; fi
	# D565: -count=1 is load-bearing, not caution. Four test packages read files
	# OUTSIDE the Go module (spec/vocab, spec/outputs.schema.json, docs/MATURITY.md,
	# CHANGELOG.md) — the doc and registry gates. Go's test cache cannot see those
	# inputs, so it replayed a PASS for a gate whose subject had changed underneath
	# it: master shipped an embedded vocabulary six slices out of date while
	# `make check` said all gates passed. A gate that can report success without
	# re-reading its subject is not a gate.
	cd go && go vet ./... && go test ./... -count=1
# D1134: the mutants' ANCHORS, not their teeth. Six of them had stopped matching the
# code they name — two because a slice of mine rewrote it hours earlier — and each
# scored as a bug re-injected that nobody could catch. The full meter says so, but the
# full meter takes half an hour and nothing runs it; this pass takes thirty seconds and
# only asks whether the substitution still lands. Cheap enough to run every time, which
# is the only property that would have caught the drift on the day it happened.
	@if [ -x scripts/mutation-gate.sh ]; then ANCHORS_ONLY=1 ./scripts/mutation-gate.sh; \
	else echo "no mutation meter in this tree (private tooling) — anchors NOT checked"; fi

# export-check: prove the PUBLIC tree is still publishable (D474). The export is the
# last step of the roadmap and the only one nothing was checking: it broke once (D340 —
# a client token across thirty files and a count gate that hard-read a file the export
# omits) and was found by a manual audit, not by a gate. The script already does the
# whole job — whitelist copy, sanitize, negative-space audit, and a STANDALONE
# `make check` proving the public tree has no hidden dependency on the private one.
#
# The destination is ALWAYS explicit and always a temp dir. Run with no argument the
# script defaults to ../groundhold-public and wipes it, which is correct for a publish
# and wrong for a check.
export-check:
	@d=$$(mktemp -d) && trap 'rm -rf "$$d"' EXIT && scripts/export-public.sh "$$d"

# repro-check: the release claims a bit-identical rebuild (BUILDINFO.txt records the
# toolchain and command precisely so a third party can do it). D477 recorded that the
# claim was ENABLED and never VERIFIED. This verifies the half that can be verified
# here: two builds of the same source, same environment, same bytes — which is what
# -trimpath is for, and what catches an embedded timestamp, an absolute path, or a
# non-deterministic link creeping in.
#
# It does NOT prove environment-independence: a different Go version or OS may produce
# different bytes, and only a third party rebuilding from BUILDINFO can close that.
# The threat model says so rather than letting this target imply more than it checks.
repro-check:
	@cd go && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.buildVersion=repro" -o /tmp/gh-repro-a ./cmd/groundhold
	@cd go && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.buildVersion=repro" -o /tmp/gh-repro-b ./cmd/groundhold
	@a=$$(sha256sum /tmp/gh-repro-a | cut -d" " -f1); b=$$(sha256sum /tmp/gh-repro-b | cut -d" " -f1); \
	rm -f /tmp/gh-repro-a /tmp/gh-repro-b; \
	if [ "$$a" != "$$b" ]; then echo "NOT REPRODUCIBLE: $$a != $$b"; exit 1; fi; \
	echo "reproducible: two builds, identical bytes ($$a)"

# race: the concurrency gate. The runtime is concurrency-heavy (lease
# acquisition, the ledger, the scenario engine); the detector must stay green.
race:
	cd go && go test -race ./...

# lint: gosec + staticcheck (config in go/.golangci.yml). Blocking in CI.
lint:
	@# D1257: golangci-lint installs into $(go env GOPATH)/bin, which is not on the
	@# PATH make's /bin/sh sees — so this target answered `golangci-lint: not found`
	@# and nobody ran it. CI runs the linter and the local gate does not, which is
	@# how an unused function reached a published branch.
	cd go && PATH="$$PATH:$$(go env GOPATH)/bin" golangci-lint run --timeout=5m

# cover: Go runtime coverage, printed as a single total.
cover:
	cd go && go test -coverprofile=cover.out ./... >/dev/null && go tool cover -func=cover.out | tail -1

# tidy: keep go.mod/go.sum minimal and correct; CI fails on drift.
tidy:
	cd go && go mod tidy && go mod verify

# mutation: the meter (docs/TESTING_STRATEGY.md). Re-injects this cycle's real bugs as
# mutants and requires the suite to CATCH each. A surviving mutant = a test with no
# teeth. Fast (curated, ~35s); safe to run per-PR.
mutation:
	./scripts/mutation-gate.sh

# Sync the compiled-in vocabulary (go:embed) with the canonical spec/vocab.
# Run after editing spec/vocab; the anti-drift test (internal/vocab) fails
# make check until embedded/ matches byte-for-byte.
embed-vocab:
	rm -f go/internal/vocab/embedded/*.yaml
	cp spec/vocab/*.yaml go/internal/vocab/embedded/
	@echo "embedded $$(ls go/internal/vocab/embedded/*.yaml | wc -l) vocab files"

# regenerate the cross-cloud capability parity matrix (spec/parity.yaml) from the
# drivers' ServiceCapabilities maps + authored structural gaps. TestParityMatrix
# (run under `make check`) fails if the committed file is stale.
parity:
	cd go && go test ./internal/parity -run TestParityMatrix -update

# D38: seeded random documents through both implementations — they must be
# indistinguishable. SEED/N are overridable: make differential N=500 SEED=7
SEED ?= 1
N ?= 30
differential:
	cd go && go build -o ../bin/groundhold-go ./cmd/groundhold
	python3 conformance/differential.py --seed $(SEED) --n $(N)

validate:
	python3 ref/groundhold.py validate spec/examples/orders-production.contract.yaml

# exit 2 = "not executable" is a valid demo outcome, only exit 1 is an error
verify:
	@python3 ref/groundhold.py verify spec/examples/orders-production.contract.yaml spec/examples/candidates/gcp-cloudsql.candidate.yaml --vocab spec/vocab || [ $$? -eq 2 ]

# D39: compile the example — REFUSED, because c-rto is only provable by a
# probe. Exit 2 here is the thesis working, not a failure.
plan:
	@cd go && go build -o ../bin/groundhold-go ./cmd/groundhold
	@bin/groundhold-go plan spec/examples/orders-production.contract.yaml spec/examples/candidates/gcp-cloudsql.candidate.yaml --vocab spec/vocab --at $(shell date -u +%Y-%m-%dT%H:%M:%SZ) || [ $$? -eq 2 ]

conformance:
	python3 conformance/run.py

# D22: drive the implementation through its CLI — the mode a Go port uses
conformance-cli:
	python3 conformance/run.py --impl "python3 ref/groundhold.py"

# D24: the Go port, measured through its own binary
conformance-go:
	cd go && go build -o ../bin/groundhold-go ./cmd/groundhold
	python3 conformance/run.py --impl "bin/groundhold-go"
