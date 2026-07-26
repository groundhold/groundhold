.PHONY: check validate verify plan conformance conformance-cli conformance-go vet differential embed-vocab parity mutation race lint cover tidy

# the gate for every change: all suites, both implementations, vet
check: vet validate conformance conformance-cli conformance-go
	@echo "all gates passed"

vet:
	@cd go && f=$$(gofmt -l .); if [ -n "$$f" ]; then echo "gofmt: unformatted files:"; echo "$$f"; exit 1; fi
	cd go && go vet ./... && go test ./...

# race: the concurrency gate. The runtime is concurrency-heavy (lease
# acquisition, the ledger, the scenario engine); the detector must stay green.
race:
	cd go && go test -race ./...

# lint: gosec + staticcheck (config in go/.golangci.yml). Blocking in CI.
lint:
	cd go && golangci-lint run --timeout=5m

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
	@bin/groundhold-go plan spec/examples/orders-production.contract.yaml spec/examples/candidates/gcp-cloudsql.candidate.yaml --vocab spec/vocab || [ $$? -eq 2 ]

conformance:
	python3 conformance/run.py

# D22: drive the implementation through its CLI — the mode a Go port uses
conformance-cli:
	python3 conformance/run.py --impl "python3 ref/groundhold.py"

# D24: the Go port, measured through its own binary
conformance-go:
	cd go && go build -o ../bin/groundhold-go ./cmd/groundhold
	python3 conformance/run.py --impl "bin/groundhold-go"
