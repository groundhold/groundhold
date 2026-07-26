#!/usr/bin/env python3
"""Differential testing harness (D38): seeded random documents and
scenarios driven through BOTH implementations' CLIs. The two runtimes
must be indistinguishable — byte-identical hashes, equal exit codes,
equal verification reports and scenario results (modulo the two
presentation-only fields: reason, observed).

Usage: python3 conformance/differential.py [--seed N] [--n N]
Deterministic for a given seed. On divergence, dumps the offending
documents to differential-failures/ and exits 1.
"""
from __future__ import annotations
import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The Go binary defaults to its compiled-in vocabulary; the Python reference has
# none built in. Disable the embedded default so both CLIs start from the same
# empty base and stay byte-identical (a case that wants vocab passes --vocab).
os.environ["GROUNDHOLD_NO_EMBEDDED_VOCAB"] = "1"
PY = [sys.executable, os.path.join(ROOT, "ref", "groundhold.py")]
GO = [os.path.join(ROOT, "bin", "groundhold-go")]
FAIL_DIR = os.path.join(ROOT, "differential-failures")

CAP_TYPES = ["capability.database.relational", "capability.storage.object",
             "capability.network.private", "capability.workload.container"]
EVENT_TYPES = ["contract.published", "candidate.verified", "plan.sealed",
               "observation.recorded", "violation.detected"]
STR_POOL = ["europe-west1", "kraków-1", "zażółć gęślą jaźń", "a\tb",
            "linia\nłamana", "🚀 rakieta", "plain-string"]
CCY = ["EUR", "USD", "PLN"]
PROTO = ["postgresql", "mysql", "redis"]
DUR_UNITS = ["ms", "s", "m", "h", "d"]
BYTE_UNITS = ["B", "KB", "MB", "GB", "TB", "KiB", "MiB", "GiB", "TiB"]
ORDERABLE = ["duration", "money", "percent", "bytes", "number"]
ANY_KIND = ORDERABLE + ["protocol", "bool", "string"]


class Gen:
    def __init__(self, rng: random.Random):
        self.r = rng

    def num(self):
        r = self.r
        k = r.random()
        if k < 0.5:
            return r.randint(0, 5000)
        if k < 0.7:
            # near and across the JSON-safe boundary (D66) — the class
            # the old harness never drew, where Go and Python diverged
            base = 2 ** 53
            return r.choice([base - 2, base - 1, base, base + 1,
                             -(base - 1), 2 ** 60, r.randint(0, 2 ** 55)])
        if k < 0.85:
            # sub-1e-17 and other awkward fractionals
            return r.choice([1e-30, 1e-20, 1e30, -0.0,
                             r.uniform(-1e6, 1e6)])
        return round(r.uniform(0, 100), r.randint(1, 3))

    def scalar(self, kind: str):
        r = self.r
        if kind == "duration":
            return f"{self.num()}{r.choice(DUR_UNITS)}"
        if kind == "money":
            if r.random() < 0.5:
                return f"{self.num()} {r.choice(CCY)}"
            return {"amount": self.num(), "currency": r.choice(CCY)}
        if kind == "percent":
            return f"{self.num()}%"
        if kind == "bytes":
            n = self.num() if r.random() < 0.3 else r.randint(1, 4096)
            return f"{n}{r.choice(BYTE_UNITS)}"
        if kind == "protocol":
            v = f"{r.choice(PROTO)}/{r.randint(1, 20)}"
            if r.random() < 0.6:
                v += f".{r.randint(0, 9)}"
            return v
        if kind == "bool":
            return r.random() < 0.5
        if kind == "number":
            return self.num()
        if kind == "string":
            return r.choice(STR_POOL)
        if kind == "list":
            return [self.scalar(r.choice(ANY_KIND))
                    for _ in range(r.randint(1, 4))]
        raise ValueError(kind)

    def tree(self, depth: int):
        r = self.r
        if depth == 0 or r.random() < 0.35:
            return r.choice([None, True, False, self.num(),
                             r.choice(STR_POOL)])
        if r.random() < 0.5:
            return [self.tree(depth - 1) for _ in range(r.randint(1, 3))]
        return {f"k{j}": self.tree(depth - 1) for j in range(r.randint(1, 3))}

    # ---- contracts / candidates ------------------------------------------

    def constraint(self, cid: str, cap_ids: list[str]) -> dict:
        r = self.r
        op = r.choice(["equals", "not-equals", "lte", "gte", "in", "not-in",
                       "subset-of", "compatible-with", "exists", "absent"])
        c = {"id": cid, "subject": r.choice(cap_ids),
             "path": f"p.{r.choice('abcdef')}{r.randint(0, 9)}", "op": op}
        if op in ("lte", "gte"):
            c["value"] = self.scalar(r.choice(ORDERABLE))
        elif op in ("in", "not-in", "subset-of"):
            c["value"] = self.scalar("list")
        elif op == "compatible-with":
            c["value"] = self.scalar("protocol")
        elif op not in ("exists", "absent"):
            c["value"] = self.scalar(r.choice(ANY_KIND + ["list"]))
        if r.random() < 0.3:
            c["verify"] = {"method": r.choice(["static", "provider-api", "probe"])}
        return c

    def contract(self, i: int) -> dict:
        r = self.r
        cap_ids = [f"cap-{x}" for x in "abc"[:r.randint(1, 3)]]
        caps = []
        for cid in cap_ids:
            cap = {"id": cid, "type": r.choice(CAP_TYPES)}
            if r.random() < 0.4:
                reqs = {}
                for _ in range(r.randint(1, 2)):
                    path = f"req.{r.choice('xyz')}{r.randint(0, 9)}"
                    if r.random() < 0.5:
                        reqs[path] = {"op": "compatible-with",
                                      "value": self.scalar("protocol")}
                    else:
                        reqs[path] = {"op": "equals",
                                      "value": self.scalar(r.choice(ANY_KIND))}
                cap["requirements"] = reqs
            caps.append(cap)
        hard = [self.constraint(f"c-{j}", cap_ids)
                for j in range(r.randint(1, 4))]
        soft = []
        for j in range(r.randint(0, 2)):
            if r.random() < 0.5:
                soft.append({"id": f"s-{j}", "subject": r.choice(cap_ids),
                             "path": f"p.s{j}",
                             "objective": r.choice(["minimize", "maximize"])})
            else:
                soft.append(self.constraint(f"s-{j}", cap_ids))
        doc = {"apiVersion": "contract/v0.1", "kind": "InfrastructureContract",
               "meta": {"id": f"diff-{i}", "environment":
                        r.choice(["test", "production"]),
                        "version": r.randint(1, 9)},
               "capabilities": caps,
               "constraints": {"hard": hard, "soft": soft}}
        if r.random() < 0.5:
            budget = {"id": "c-budget", "subject": r.choice(cap_ids),
                      "path": "cost.monthly", "op": "lte",
                      "value": self.scalar("money")}
            if r.random() < 0.3:
                budget["severity"] = r.choice(["hard", "soft"])
            doc["budget"] = [budget]
        if r.random() < 0.4:
            hard_ids = [c["id"] for c in hard]
            doc["assumptions"] = [{
                "id": f"a-{j}", "statement": r.choice(STR_POOL),
                "status": r.choice(["declared", "inferred", "assumed", "unknown"]),
                "confidence": round(r.uniform(0, 1), 2),
                "affects": r.sample(hard_ids, r.randint(1, len(hard_ids))),
            } for j in range(r.randint(1, 2))]
        if r.random() < 0.3:
            doc["autonomy"] = {"forbidden": [
                {"disable": r.choice([c["id"] for c in hard])},
                {"delete_stateful": True}]}
        return doc

    def candidate(self, contract_doc: dict) -> dict:
        r = self.r
        paths_by_cap: dict[str, set] = {
            c["id"]: set() for c in contract_doc["capabilities"]}
        cblock = contract_doc.get("constraints") or {}
        for group in (cblock.get("hard") or []) + (cblock.get("soft") or []) \
                + (contract_doc.get("budget") or []):
            if group.get("subject") in paths_by_cap and group.get("path"):
                paths_by_cap[group["subject"]].add(group["path"])
        for cap in contract_doc["capabilities"]:
            for path in (cap.get("requirements") or {}):
                paths_by_cap[cap["id"]].add(path)

        caps = {}
        for cap_id, paths in paths_by_cap.items():
            attrs = {}
            for path in sorted(paths):
                roll = r.random()
                if roll < 0.2:
                    continue  # undeclared -> unknown
                if roll < 0.35:
                    attrs[path] = {
                        "value": self.scalar(r.choice(ANY_KIND + ["list"])),
                        "status": r.choice(["declared", "inferred", "assumed"]),
                        "confidence": round(r.uniform(0, 1), 2),
                        "source": r.choice(STR_POOL)}
                elif roll < 0.4:
                    attrs[path] = {"status": "unknown"}
                else:
                    attrs[path] = self.scalar(r.choice(ANY_KIND + ["list"]))
            for j in range(r.randint(0, 2)):
                attrs[f"extra.e{j}"] = self.scalar(r.choice(ANY_KIND))
            body = {"attributes": attrs}
            if r.random() < 0.5:
                body["provider"] = r.choice(["gcp", "aws"])
                body["service"] = r.choice(["cloudsql", "rds", "gcs"])
            if r.random() < 0.4:
                body["implementation"] = {"detail": self.tree(2)}
            caps[cap_id] = body
        contract_id = contract_doc["meta"]["id"]
        if r.random() < 0.1:
            contract_id = "some-other-contract"
        return {"apiVersion": "candidate/v0.1",
                "kind": "ImplementationCandidate",
                "contract": contract_id, "capabilities": caps}

    def corrupt_contract(self, doc: dict) -> dict:
        r = self.r
        doc = json.loads(json.dumps(doc))  # deep copy
        hard = doc["constraints"]["hard"]
        mutation = r.choice(["dup-id", "bad-op", "dangling-affects"])
        if mutation == "dup-id":
            hard.append(dict(hard[0]))
        elif mutation == "bad-op":
            hard.append({"id": "c-bad", "subject": doc["capabilities"][0]["id"],
                         "path": "p.x", "op": "matches", "value": "x"})
        else:
            doc["assumptions"] = [{"id": "a-bad", "statement": "x",
                                   "status": "assumed", "affects": ["no-such"]}]
        return doc

    # ---- events / plans / scenarios --------------------------------------

    def event(self, i: int) -> dict:
        r = self.r
        ev = {"type": r.choice(EVENT_TYPES),
              "environment": r.choice(["test", "production"]),
              "capabilities": r.sample(["db", "cache"], r.randint(1, 2)),
              "occurredAt": f"2026-07-11T09:{i % 60:02d}:00Z",
              "actor": {"id": r.choice(["alice", "runtime-eu1", "agent-7"]),
                        "type": r.choice(["human", "agent", "runtime"])},
              "body": {"detail": self.tree(3)}}
        if r.random() < 0.3:
            ev["idempotencyKey"] = f"key-{i}"
        return {"apiVersion": "state/v0", "kind": "LedgerEvent", "event": ev}

    def corrupt_event(self, doc: dict) -> dict:
        doc = json.loads(json.dumps(doc))
        if self.r.random() < 0.5:
            doc["event"]["type"] = "lease.stolen"
        else:
            doc["event"]["capabilities"] = []
        return doc

    def _hex(self) -> str:
        return "sha256:" + "".join(
            self.r.choice("0123456789abcdef") for _ in range(64))

    def plan(self, i: int) -> dict:
        r = self.r
        caps = ["cap-a", "cap-b"][:r.randint(1, 2)]
        actions = []
        for j in range(r.randint(1, 4)):
            a = {"id": f"a-{j}", "capability": r.choice(caps),
                 "operation": r.choice(["create", "update", "replace",
                                        "delete", "adopt", "noop"]),
                 "target": f"t-{j}", "idempotencyKey": f"k-{i}-{j}",
                 "risk": {
                     "reversibility": f"R{r.randint(0, 4)}",
                     "dataLoss": r.choice(["none", "possible", "certain"]),
                     "downtime": r.choice(["none", "possible", "certain"]),
                     "securityExposure": r.choice(["none", "possible", "certain"]),
                     "costDelta": {"amount": self.num(),
                                   "currency": r.choice(CCY)},
                     "identityReplacement": r.random() < 0.3}}
            if j > 0 and r.random() < 0.5:
                a["dependsOn"] = r.sample(
                    [f"a-{k}" for k in range(j)], r.randint(1, j))
            actions.append(a)
        pre = [{"type": "report-executable"}]
        if r.random() < 0.4:
            pre.append({"type": r.choice(["no-assumed-basis", "within-autonomy"])})
        return {"apiVersion": "plan/v0", "kind": "SealedPlan", "plan": {
            "contract": f"diff-{i}", "environment": "test",
            "reads": {"contractHash": self._hex(),
                      "candidateHash": self._hex(),
                      "heads": {c: (self._hex() if r.random() < 0.5
                                    else "genesis") for c in caps},
                      "toolchain": {"compiler": "diff/0", "spec": "contract/v0.1"}},
            "writes": caps, "actions": actions, "preconditions": pre}}

    def corrupt_plan(self, doc: dict) -> dict:
        r = self.r
        doc = json.loads(json.dumps(doc))
        p = doc["plan"]
        mutation = r.choice(["bad-op", "no-precondition", "ghost-dep"])
        if mutation == "bad-op":
            p["actions"][0]["operation"] = "destroy"
        elif mutation == "no-precondition":
            p["preconditions"] = [{"type": "within-autonomy"}]
        else:
            p["actions"][0]["dependsOn"] = ["a-ghost"]
        return doc

    def scenario(self, i: int) -> dict:
        r = self.r
        steps = []
        appended = []
        for j in range(r.randint(3, 10)):
            roll = r.random()
            if roll < 0.15:
                steps.append({"tick": r.randint(1, 5)})
                continue
            if roll < 0.3 and appended:
                steps.append({"checkHeads": {
                    r.choice(["db", "cache"]):
                        r.choice(["genesis", f"@{r.choice(appended)}"])}})
                continue
            etype = r.choice([
                "lease.acquired", "lease.released", "lease.renewed",
                "lease.broken", "binding.updated", "apply.started",
                "apply.finished", "apply.failed", "operation.receipt",
                "contract.published", "plan.sealed"])
            a = {"type": etype,
                 "capabilities": r.sample(["db", "cache"], r.randint(1, 2)),
                 "actor": r.choice(["worker-a", "worker-b"])}
            if etype == "lease.acquired":
                a["body"] = {"ttlSeconds": r.randint(1, 6)}
            elif etype in ("lease.released", "lease.renewed", "binding.updated",
                           "apply.started", "apply.finished", "apply.failed"):
                a["fencingToken"] = r.randint(1, 3)
            elif etype == "lease.broken":
                if r.random() < 0.5:
                    a["body"] = {"adoptReceipts": True}
            elif etype == "operation.receipt":
                a["body"] = {"operationId": f"op-{r.randint(1, 3)}",
                             "status": r.choice(["pending", "succeeded",
                                                 "failed", "unknown"])}
            step = {"append": a}
            if r.random() < 0.3 and appended:
                step["expectedHeads"] = {
                    a["capabilities"][0]:
                        r.choice(["genesis", f"@{r.choice(appended)}"])}
            steps.append(step)
            appended.append(len(steps))
        return {"apiVersion": "scenario/v0", "kind": "ConcurrencyScenario",
                "steps": steps}


# ---- comparison -------------------------------------------------------------

def run(impl, args):
    return subprocess.run(impl + args, capture_output=True, text=True)


def normalize_report(report: dict) -> dict:
    for v in report.get("verdicts", []):
        v.pop("reason", None)
        v.pop("observed", None)
    return report


def normalize_results(results: list) -> list:
    for r in results:
        r.pop("reason", None)
    return results


class Diff:
    def __init__(self):
        self.checked = 0
        self.failures = 0

    def fail(self, what: str, artifacts: dict, detail: str):
        self.failures += 1
        os.makedirs(FAIL_DIR, exist_ok=True)
        stem = os.path.join(FAIL_DIR, f"{what}-{self.failures}")
        for name, content in artifacts.items():
            with open(f"{stem}-{name}", "w") as f:
                f.write(content)
        print(f"DIVERGENCE [{what}]: {detail}")
        print(f"  artifacts: {stem}-*")

    def check_raw_hash(self, what: str, text: str, path: str):
        """Hash a VERBATIM yaml document (no safe_dump) in both CLIs —
        the once-blind ambiguous-scalar class (yes/on/12:30/1e3)."""
        self.checked += 1
        with open(path, "w") as f:
            f.write(text)
        a, b = run(PY, ["hash", path]), run(GO, ["hash", path])
        if (a.returncode == 0) != (b.returncode == 0) or \
                (a.returncode == 0 and a.stdout != b.stdout):
            self.fail(what, {"raw.yaml": text},
                      f"raw-token hash diverges: py={a.stdout.strip()!r}/"
                      f"{a.stderr.strip()!r} go={b.stdout.strip()!r}/"
                      f"{b.stderr.strip()!r}")

    def check_hash(self, what: str, doc: dict, path: str):
        self.checked += 1
        a, b = run(PY, ["hash", path]), run(GO, ["hash", path])
        if (a.returncode == 0) != (b.returncode == 0):
            self.fail(what, {"doc.yaml": yaml.safe_dump(doc)},
                      f"exit codes differ: py={a.returncode} go={b.returncode} "
                      f"(py: {a.stderr.strip()!r} go: {b.stderr.strip()!r})")
        elif a.returncode == 0 and a.stdout != b.stdout:
            self.fail(what, {"doc.yaml": yaml.safe_dump(doc)},
                      f"hashes differ: py={a.stdout.strip()} go={b.stdout.strip()}")

    def check_verify(self, cdoc: dict, kdoc: dict, cpath: str, kpath: str):
        self.checked += 1
        a = run(PY, ["verify", cpath, kpath, "--json"])
        b = run(GO, ["verify", cpath, kpath, "--json"])
        arts = {"contract.yaml": yaml.safe_dump(cdoc),
                "candidate.yaml": yaml.safe_dump(kdoc)}
        if a.returncode != b.returncode:
            self.fail("verify", arts,
                      f"exit codes differ: py={a.returncode} go={b.returncode} "
                      f"(py: {a.stderr.strip()!r} go: {b.stderr.strip()!r})")
            return
        if a.returncode not in (0, 2):
            return  # both rejected structurally — consistent
        ra = normalize_report(json.loads(a.stdout))
        rb = normalize_report(json.loads(b.stdout))
        if ra != rb:
            arts["report-py.json"] = json.dumps(ra, indent=2, ensure_ascii=False)
            arts["report-go.json"] = json.dumps(rb, indent=2, ensure_ascii=False)
            self.fail("verify", arts, "normalized reports differ")

    def check_scenario(self, doc: dict, path: str):
        self.checked += 1
        a, b = run(PY, ["scenario", path]), run(GO, ["scenario", path])
        arts = {"scenario.yaml": yaml.safe_dump(doc)}
        if (a.returncode == 0) != (b.returncode == 0):
            self.fail("scenario", arts,
                      f"exit codes differ: py={a.returncode} go={b.returncode} "
                      f"(py: {a.stderr.strip()!r} go: {b.stderr.strip()!r})")
            return
        if a.returncode != 0:
            return
        ra = normalize_results(json.loads(a.stdout)["results"])
        rb = normalize_results(json.loads(b.stdout)["results"])
        if ra != rb:
            arts["results-py.json"] = json.dumps(ra, indent=2)
            arts["results-go.json"] = json.dumps(rb, indent=2)
            self.fail("scenario", arts, "scenario results differ")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--n", type=int, default=30)
    args = ap.parse_args()
    if os.path.isdir(FAIL_DIR):
        shutil.rmtree(FAIL_DIR)

    gen = Gen(random.Random(args.seed))
    diff = Diff()
    with tempfile.TemporaryDirectory() as td:
        def write(name, doc):
            path = os.path.join(td, name)
            with open(path, "w") as f:
                yaml.safe_dump(doc, f, allow_unicode=True)
            return path

        for i in range(args.n):
            cdoc = gen.contract(i)
            if gen.r.random() < 0.1:
                bad = gen.corrupt_contract(cdoc)
                diff.check_hash("contract", bad, write("c.yaml", bad))
                continue
            kdoc = gen.candidate(cdoc)
            cpath, kpath = write("c.yaml", cdoc), write("k.yaml", kdoc)
            diff.check_hash("contract", cdoc, cpath)
            diff.check_hash("candidate", kdoc, kpath)
            diff.check_verify(cdoc, kdoc, cpath, kpath)

        for i in range(args.n):
            edoc = gen.event(i)
            if gen.r.random() < 0.1:
                edoc = gen.corrupt_event(edoc)
            diff.check_hash("event", edoc, write("e.yaml", edoc))

        for i in range(args.n):
            pdoc = gen.plan(i)
            if gen.r.random() < 0.1:
                pdoc = gen.corrupt_plan(pdoc)
            diff.check_hash("plan", pdoc, write("p.yaml", pdoc))

        for i in range(args.n):
            sdoc = gen.scenario(i)
            diff.check_scenario(sdoc, write("s.yaml", sdoc))

        # the ambiguous-scalar class safe_dump quotes and the harness was
        # blind to (review fix): YAML 1.1 vs 1.2 resolution — both
        # runtimes must resolve these UNQUOTED tokens identically or the
        # canonical hash (and every signature over it) diverges.
        tokens = ["yes", "on", "no", "off", "y", "n", "Yes", "YES",
                  "true", "false", "True",
                  "12:30:00", "1:20", "1e3", "1.5e3", ".5", "0x1f",
                  "0o17", "010", "0b101", "null", "~"]
        rawpath = os.path.join(td, "raw.yaml")
        raw_tmpl = (
            "apiVersion: state/v0\n"
            "kind: LedgerEvent\n"
            "event:\n"
            "  type: observation.recorded\n"
            "  environment: test\n"
            "  capabilities: [db]\n"
            '  occurredAt: "2026-07-11T12:00:00Z"\n'
            "  actor: { id: s, type: runtime }\n"
            "  body: { note: __TOK__ }\n"
        )
        for tok in tokens:
            diff.check_raw_hash(
                f"raw-token:{tok}", raw_tmpl.replace("__TOK__", tok), rawpath)

    print(f"\n{diff.checked} differential checks, "
          f"{diff.failures} divergence(s) (seed={args.seed}, n={args.n})")
    return 1 if diff.failures else 0


if __name__ == "__main__":
    sys.exit(main())
