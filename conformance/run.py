#!/usr/bin/env python3
"""Conformance runner. Executes every case in cases/*.yaml against an
implementation.

Two modes:
  library (default)   imports the Python reference directly — fast path
  --impl "<command>"  drives ANY implementation through its CLI:
                        <command> verify <contract> <candidate> --json

The CLI protocol is part of the spec (D22): exit 0 = executable,
1 = structural error in a document, 2 = not executable; the JSON report
on stdout; load rejections print 'contract error:' / 'candidate error:'
on stderr. The future Go runtime must pass the exact same cases via
--impl — no Python involved in what it is measured against.
"""
import glob
import json
import os
import shlex
import subprocess
import sys
import tempfile

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ref"))
from groundholdlib import canonical  # noqa: E402
from groundholdlib.contract import load_contract, load_candidate, ContractError  # noqa: E402
from groundholdlib.plan import load_plan  # noqa: E402
from groundholdlib.scenario import run_scenario  # noqa: E402
from groundholdlib.state import load_event  # noqa: E402
from groundholdlib.verify import verify  # noqa: E402
from groundholdlib.vocab import load_vocab_dir  # noqa: E402

# The Go binary ships the full vocabulary compiled in (go:embed) and uses it by
# default. The conformance cases were written to drive the vocabulary explicitly
# — --vocab when a case ships one, empty otherwise — so disable the embedded
# default for every CLI subprocess the suite spawns. This keeps both
# implementations measured against the exact vocab-source semantics the cases
# assume (the built-in vocabulary itself is covered by Go unit tests).
os.environ["GROUNDHOLD_NO_EMBEDDED_VOCAB"] = "1"

# The suite drives the CLI against the FAKE provider deterministically. Declare it
# explicitly (F4 fail-closed): provider verbs refuse a defaulted fake, so the
# harness names the provider it means — the same deliberate choice a real operator
# must make. Subprocesses inherit this env.
os.environ["GROUNDHOLD_PROVIDER"] = "fake"


def check_report(report: dict, expect: dict) -> list[str]:
    failures = []
    if report["executable"] != expect["executable"]:
        failures.append(
            f"executable: expected {expect['executable']}, got {report['executable']}")
    for key in ("specVersion", "contractHash", "candidateHash", "code"):
        if key in expect and report.get(key) != expect[key]:
            failures.append(f"{key}: expected {expect[key]}, "
                            f"got {report.get(key)}")
    by_id = {v["constraint"]: v for v in report["verdicts"]}
    for cid, want in (expect.get("verdicts") or {}).items():
        got = by_id.get(cid, {}).get("verdict", "<missing>")
        if got != want:
            failures.append(f"{cid}: expected {want}, got {got}")
    for cid, want in (expect.get("basis") or {}).items():
        got = by_id.get(cid, {}).get("basis", "<missing>")
        if got != want:
            failures.append(f"{cid} basis: expected {want}, got {got}")
    for cid, want in (expect.get("pathInVocabulary") or {}).items():
        got = by_id.get(cid, {}).get("pathInVocabulary", "<missing>")
        if got != want:
            failures.append(f"{cid} pathInVocabulary: expected {want}, got {got}")
    return failures


def _write_docs(td: str, case: dict) -> tuple[str, str, str | None]:
    cpath = os.path.join(td, "contract.yaml")
    kpath = os.path.join(td, "candidate.yaml")
    with open(cpath, "w") as f:
        yaml.safe_dump(case["contract"], f)
    with open(kpath, "w") as f:
        yaml.safe_dump(case.get("candidate"), f)
    vdir = None
    if case.get("vocab"):
        vdir = os.path.join(td, "vocab")
        os.makedirs(vdir)
        for i, doc in enumerate(case["vocab"]):
            with open(os.path.join(vdir, f"v{i}.yaml"), "w") as f:
                yaml.safe_dump(doc, f)
    return cpath, kpath, vdir


def _hash_document(path: str, doc: dict) -> str:
    kind = doc.get("kind") if isinstance(doc, dict) else None
    if kind == "InfrastructureContract":
        return canonical.hash_contract(load_contract(path))
    if kind == "ImplementationCandidate":
        return canonical.hash_candidate(load_candidate(path))
    if kind == "LedgerEvent":
        return canonical.hash_event(load_event(path))
    if kind == "SealedPlan":
        return canonical.hash_plan(load_plan(path))
    if kind == "DiscoveryDocument":
        return canonical.hash_discovery(doc)
    raise ContractError(f"unknown kind {kind!r}")


def run_hash_case_library(case: dict) -> list[str]:
    expect = case["expect"]
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "document.yaml")
        with open(path, "w") as f:
            yaml.safe_dump(case["document"], f)
        try:
            got = _hash_document(path, case["document"])
        except ContractError as e:
            if expect.get("error") == "document":
                return []
            return [f"unexpected document load error: {e}"]
    if expect.get("error"):
        return ["expected document load error, document loaded"]
    if got != expect["hash"]:
        return [f"hash: expected {expect['hash']}, got {got}"]
    return []


def run_hash_case_cli(case: dict, impl: list[str]) -> list[str]:
    expect = case["expect"]
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "document.yaml")
        with open(path, "w") as f:
            yaml.safe_dump(case["document"], f)
        proc = subprocess.run(impl + ["hash", path],
                              capture_output=True, text=True)
    if expect.get("error"):
        failures = []
        if proc.returncode != 1:
            failures.append(f"exit code: expected 1, got {proc.returncode}")
        if not proc.stderr.startswith("document error:"):
            failures.append(
                f"stderr: expected 'document error:' prefix, got {proc.stderr!r}")
        return failures
    if proc.returncode != 0:
        return [f"exit code: expected 0, got {proc.returncode}; "
                f"stderr: {proc.stderr!r}"]
    got = proc.stdout.strip()
    if got != expect["hash"]:
        return [f"hash: expected {expect['hash']}, got {got}"]
    return []


def _compare_results(got: list, want: list) -> list[str]:
    failures = []
    if len(got) != len(want):
        failures.append(f"steps: expected {len(want)} results, got {len(got)}")
    for i, w in enumerate(want):
        if i >= len(got):
            break
        for k, v in w.items():
            if got[i].get(k) != v:
                failures.append(
                    f"step {i + 1} {k}: expected {v!r}, got {got[i].get(k)!r}")
    return failures


def run_scenario_case_library(case: dict) -> list[str]:
    expect = case["expect"]
    try:
        results = run_scenario(case["scenario"])
    except ContractError as e:
        if expect.get("error") == "scenario":
            return []
        return [f"unexpected scenario error: {e}"]
    if expect.get("error"):
        return ["expected scenario error, scenario ran"]
    return _compare_results(results, expect.get("results") or [])


def run_scenario_case_cli(case: dict, impl: list[str]) -> list[str]:
    expect = case["expect"]
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "scenario.yaml")
        with open(path, "w") as f:
            yaml.safe_dump(case["scenario"], f)
        proc = subprocess.run(impl + ["scenario", path],
                              capture_output=True, text=True)
    if expect.get("error"):
        failures = []
        if proc.returncode != 1:
            failures.append(f"exit code: expected 1, got {proc.returncode}")
        if not proc.stderr.startswith("scenario error:"):
            failures.append(
                f"stderr: expected 'scenario error:' prefix, got {proc.stderr!r}")
        return failures
    if proc.returncode != 0:
        return [f"exit code: expected 0, got {proc.returncode}; "
                f"stderr: {proc.stderr!r}"]
    try:
        results = json.loads(proc.stdout)["results"]
    except (json.JSONDecodeError, KeyError) as e:
        return [f"stdout is not a scenario result: {e}"]
    return _compare_results(results, case["expect"].get("results") or [])


def run_forecast_case_cli(case: dict, impl: list[str]) -> list[str]:
    expect = case["expect"]
    spec = case["forecast"]
    with tempfile.TemporaryDirectory() as td:
        ppath = os.path.join(td, "plan.yaml")
        kpath = os.path.join(td, "candidate.yaml")
        with open(ppath, "w") as f:
            yaml.safe_dump(spec["plan"], f)
        with open(kpath, "w") as f:
            yaml.safe_dump(spec["candidate"], f)
        cmd = impl + ["forecast", ppath, kpath]
        for key, flag in (("heads", "--heads"), ("bindings", "--bindings"),
                          ("observations", "--observations")):
            if spec.get(key):
                path = os.path.join(td, f"{key}.yaml")
                payload = spec[key]
                if key == "observations":
                    payload = {"observations": payload}
                with open(path, "w") as f:
                    yaml.safe_dump(payload, f)
                cmd += [flag, path]
        if spec.get("at"):
            cmd += ["--at", spec["at"]]
        proc = subprocess.run(cmd, capture_output=True, text=True)
    if expect.get("error"):
        failures = []
        if proc.returncode != 1:
            failures.append(f"exit code: expected 1, got {proc.returncode}")
        if not proc.stderr.startswith("forecast error:"):
            failures.append(
                f"stderr: expected 'forecast error:' prefix, got {proc.stderr!r}")
        return failures
    if proc.returncode != 0:
        return [f"exit code: expected 0, got {proc.returncode}; "
                f"stderr: {proc.stderr!r}"]
    try:
        fc = json.loads(proc.stdout)["forecast"]
    except (json.JSONDecodeError, KeyError) as e:
        return [f"stdout is not a forecast: {e}"]
    failures = []
    if "freshPlan" in expect and fc.get("freshPlan") != expect["freshPlan"]:
        failures.append(f"freshPlan: expected {expect['freshPlan']}, "
                        f"got {fc.get('freshPlan')}")
    by_id = {a["id"]: a for a in fc.get("actions") or []}
    for aid, want in (expect.get("effects") or {}).items():
        got = by_id.get(aid, {}).get("effect", "<missing>")
        if got != want:
            failures.append(f"{aid} effect: expected {want}, got {got}")
    for aid, want in (expect.get("reasons") or {}).items():
        got = by_id.get(aid, {}).get("reason", "<missing>")
        if got != want:
            failures.append(f"{aid} reason: expected {want}, got {got}")
    for aid, wantmap in (expect.get("attributes") or {}).items():
        preds = {a["path"]: (a.get("prediction"), a.get("reason"))
                 for a in by_id.get(aid, {}).get("attributes") or []}
        for path, want in wantmap.items():
            got_pred, got_reason = preds.get(path, ("<missing>", None))
            if isinstance(want, dict):
                if got_pred != want.get("prediction") \
                        or got_reason != want.get("reason"):
                    failures.append(
                        f"{aid}.{path}: expected {want}, "
                        f"got ({got_pred}, {got_reason})")
            elif got_pred != want:
                failures.append(
                    f"{aid}.{path}: expected {want}, got {got_pred}")
    return failures


def _check_next(got: dict, want: dict) -> list[str]:
    """Structural assertion on a refusal's advisory `next` (D230). Paths in argv
    are the operator's own (tempdir-varying), so we assert kind/runnable and that
    required tokens are PRESENT, not the exact argv (that is a unit-level golden)."""
    fails = []
    if got is None:
        return [f"expected a next {want!r}, got none"]
    if "kind" in want and got.get("kind") != want["kind"]:
        fails.append(f"next.kind: expected {want['kind']!r}, got {got.get('kind')!r}")
    if "runnable" in want and bool(got.get("runnable")) != bool(want["runnable"]):
        fails.append(f"next.runnable: expected {want['runnable']}, got {got.get('runnable')}")
    for tok in want.get("argvContains") or []:
        if tok not in (got.get("argv") or []):
            fails.append(f"next.argv missing token {tok!r} (argv={got.get('argv')})")
    for tok in want.get("retryContains") or []:
        if tok not in (got.get("retry") or []):
            fails.append(f"next.retry missing token {tok!r}")
    if "editPointer" in want:
        ptr = (got.get("edit") or {}).get("pointer")
        if ptr != want["editPointer"]:
            fails.append(f"next.edit.pointer: expected {want['editPointer']!r}, got {ptr!r}")
    return fails


def run_plan_case_cli(case: dict, impl: list[str]) -> list[str]:
    expect = case["expect"]
    spec = case["plan"]
    with tempfile.TemporaryDirectory() as td:
        cpath = os.path.join(td, "contract.yaml")
        kpath = os.path.join(td, "candidate.yaml")
        with open(cpath, "w") as f:
            yaml.safe_dump(spec["contract"], f)
        with open(kpath, "w") as f:
            yaml.safe_dump(spec["candidate"], f)
        cmd = impl + ["plan", cpath, kpath]
        if spec.get("vocab"):
            vdir = os.path.join(td, "vocab")
            os.makedirs(vdir)
            for i, doc in enumerate(spec["vocab"]):
                with open(os.path.join(vdir, f"v{i}.yaml"), "w") as f:
                    yaml.safe_dump(doc, f)
            cmd += ["--vocab", vdir]
        if spec.get("ledger"):
            lpath = os.path.join(td, "ledger.jsonl")
            seed_ledger(lpath, spec["ledger"])
            cmd += ["--ledger", lpath]
        elif spec.get("withLedger"):
            # D230: pass an (empty) --ledger so a refusal's `next` can build the
            # `observe --ledger ... --record` fix command (the honest scenario:
            # the operator has a ledger + supplied observations that went stale).
            lpath = os.path.join(td, "ledger.jsonl")
            open(lpath, "w").close()
            cmd += ["--ledger", lpath]
        if spec.get("project"):
            cmd += ["--project", spec["project"]]
        for key, flag in (("bindings", "--bindings"),
                          ("observations", "--observations")):
            if spec.get(key):
                path = os.path.join(td, f"{key}.yaml")
                payload = spec[key]
                if key == "observations":
                    payload = {"observations": payload}
                with open(path, "w") as f:
                    yaml.safe_dump(payload, f)
                cmd += [flag, path]
        if spec.get("at"):
            cmd += ["--at", spec["at"]]
        proc = subprocess.run(cmd, capture_output=True, text=True)
    if expect.get("error"):
        failures = []
        if proc.returncode != 2:
            failures.append(f"exit code: expected 2, got {proc.returncode}; "
                            f"stderr: {proc.stderr!r}")
        if not proc.stderr.startswith("plan refused:"):
            failures.append(
                f"stderr: expected 'plan refused:' prefix, got {proc.stderr!r}")
        # D65: exactly one machine-readable refusal object on stdout
        try:
            refusal = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            failures.append(f"refusal stdout is not one JSON object: {e}")
            refusal = {}
        if refusal.get("status") != "refused":
            failures.append(f"refusal status: got {refusal.get('status')!r}")
        if "code" in expect and refusal.get("code") != expect["code"]:
            failures.append(f"refusal code: expected {expect['code']!r}, "
                            f"got {refusal.get('code')!r}")
        # D230: the advisory next. Asserted STRUCTURALLY — the operator's paths in
        # argv vary per tempdir, so the byte-exact argv is pinned at the unit level;
        # here we pin the CLI integration (kind, runnable, argv tokens present).
        if "next" in expect:
            failures += _check_next(refusal.get("next"), expect["next"])
        return failures
    if proc.returncode != 0:
        return [f"exit code: expected 0, got {proc.returncode}; "
                f"stderr: {proc.stderr!r}"]
    try:
        doc = json.loads(proc.stdout)["plan"]
    except (json.JSONDecodeError, KeyError) as e:
        return [f"stdout is not a plan: {e}"]
    failures = []
    by_id = {a["id"]: a for a in doc.get("actions") or []}
    for aid, want in (expect.get("actions") or {}).items():
        a = by_id.get(aid)
        if a is None:
            failures.append(f"action {aid}: missing")
            continue
        if isinstance(want, str):
            want = {"operation": want}
        if a.get("operation") != want.get("operation"):
            failures.append(f"{aid} operation: expected "
                            f"{want.get('operation')}, got {a.get('operation')}")
        if "changes" in want:
            got_paths = [ch["path"] for ch in a.get("changes") or []]
            if got_paths != want["changes"]:
                failures.append(f"{aid} changes: expected {want['changes']}, "
                                f"got {got_paths}")
        if "requiredPermissions" in want:
            got = a.get("requiredPermissions") or []
            if got != want["requiredPermissions"]:
                failures.append(f"{aid} requiredPermissions: expected "
                                f"{want['requiredPermissions']}, got {got}")
        if "dependsOn" in want:
            got = a.get("dependsOn") or []
            if got != want["dependsOn"]:
                failures.append(f"{aid} dependsOn: expected "
                                f"{want['dependsOn']}, got {got}")
        if "references" in want:
            got = a.get("references") or []
            if got != want["references"]:
                failures.append(f"{aid} references: expected "
                                f"{want['references']}, got {got}")
        if "folds" in want:
            got = a.get("folds") or []
            if got != want["folds"]:
                failures.append(f"{aid} folds: expected "
                                f"{want['folds']}, got {got}")
    for aid in (expect.get("absentActions") or []):
        if aid in by_id:
            failures.append(f"action {aid}: expected absent, present")
    # unverified (D249): capabilities the plan sealed but could not verify (a
    # non-observable / blind-observer attribute). Each named capability must appear
    # in the plan's `unverified` — isolation, never a frozen compile.
    if "unverified" in expect:
        got_unver = {u["capability"] for u in doc.get("unverified") or []}
        for cap in expect["unverified"]:
            if cap not in got_unver:
                failures.append(f"unverified: expected capability {cap!r}, "
                                f"got {sorted(got_unver)}")
    if "provider" in expect and doc.get("reads", {}).get("provider") != expect["provider"]:
        failures.append(f"provider: expected {expect['provider']!r}, "
                        f"got {doc.get('reads', {}).get('provider')!r}")
    return failures


def seed_ledger(path: str, events: list[dict]) -> dict:
    """Write a seed ledger, stitching the hash chain (C2): each event's
    prev pins the current head of every capability it lists, computed
    with the same hash_event both implementations use. Returns the final
    heads so a case can pin reads.heads to the stitched values. Manual
    seeds thus carry a valid chain, exactly as the runtime would write."""
    heads: dict = {}
    with open(path, "w") as f:
        for doc in events:
            ev = doc["event"]
            caps = ev.get("capabilities") or []
            ev["prev"] = {c: heads.get(c, "genesis") for c in caps}
            h = canonical.hash_event(doc)
            for c in caps:
                heads[c] = h
            f.write(json.dumps(doc) + "\n")
    return heads


def _check_json_result(tag: str, proc, expect: dict,
                       failures: list[str]) -> dict:
    if "exit" in expect and proc.returncode != expect["exit"]:
        failures.append(f"{tag} exit: expected {expect['exit']}, "
                        f"got {proc.returncode}; stderr: {proc.stderr!r}")
    try:
        res = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        failures.append(f"{tag} stdout is not JSON: {e}")
        return {}
    for key in ("status", "events", "bindings", "code"):
        if key in expect and res.get(key) != expect[key]:
            failures.append(f"{tag} {key}: expected {expect[key]!r}, "
                            f"got {res.get(key)!r}")
    if "reasonContains" in expect and not any(
            expect["reasonContains"] in r for r in res.get("reasons") or []):
        failures.append(f"{tag} reasons: expected one to contain "
                        f"{expect['reasonContains']!r}, "
                        f"got {res.get('reasons')!r}")
    return res


def run_then_steps(steps, impl, td, cpath, kpath, lpath,
                   failures: list[str]) -> None:
    """Post-apply steps (D71/D72): resume with literal keys, plan
    --deposed (saving the sealed plan), apply of that saved plan, and a
    deposed listing — later steps prove what earlier ones wrote."""
    saved_plan = os.path.join(td, "deposed-plan.json")
    for i, step in enumerate(steps):
        tag = f"then {i}"
        expect = step.get("expect") or {}
        if "resume" in step:
            s = step["resume"] or {}
            cmd = impl + ["resume", cpath, "--ledger", lpath,
                          "--at", s["at"]]
            for k in s.get("unknownKeys") or []:
                cmd += ["--unknown-key", k]
            for k in s.get("failKeys") or []:
                cmd += ["--fail-key", k]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            _check_json_result(f"{tag} (resume)", proc, expect, failures)
        elif "planDeposed" in step:
            s = step["planDeposed"] or {}
            step_cpath = cpath
            if s.get("contract"):
                step_cpath = os.path.join(td, f"contract-then-{i}.yaml")
                with open(step_cpath, "w") as f:
                    yaml.safe_dump(s["contract"], f)
            cmd = impl + ["plan", step_cpath, kpath, "--deposed",
                          "--ledger", lpath, "--at", s["at"]]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            tag = f"{tag} (planDeposed)"
            if "exit" in expect and proc.returncode != expect["exit"]:
                failures.append(f"{tag} exit: expected {expect['exit']}, "
                                f"got {proc.returncode}; "
                                f"stderr: {proc.stderr!r}")
                continue
            if proc.returncode == 0:
                with open(saved_plan, "w") as f:
                    f.write(proc.stdout)
                doc = json.loads(proc.stdout).get("plan") or {}
                by_id = {a["id"]: a for a in doc.get("actions") or []}
                for aid, want in (expect.get("actions") or {}).items():
                    a = by_id.get(aid)
                    if a is None:
                        failures.append(f"{tag} action {aid}: missing "
                                        f"(got {sorted(by_id)})")
                        continue
                    for k, v in want.items():
                        if a.get(k) != v:
                            failures.append(f"{tag} {aid}.{k}: expected "
                                            f"{v!r}, got {a.get(k)!r}")
            else:
                refusal = json.loads(proc.stdout)
                if "code" in expect and refusal.get("code") != expect["code"]:
                    failures.append(f"{tag} code: expected "
                                    f"{expect['code']!r}, "
                                    f"got {refusal.get('code')!r}")
        elif "applySaved" in step:
            s = step["applySaved"] or {}
            cmd = impl + ["apply", cpath, kpath, saved_plan,
                          "--ledger", lpath, "--at", s["at"]]
            for k in s.get("failKeys") or []:
                cmd += ["--fail-key", k]
            for k in s.get("unknownKeys") or []:
                cmd += ["--unknown-key", k]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            _check_json_result(f"{tag} (applySaved)", proc, expect, failures)
        elif "deposed" in step:
            s = step["deposed"] or {}
            cmd = impl + ["deposed", "--ledger", lpath]
            if s.get("all"):
                cmd += ["--all"]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            got = json.loads(proc.stdout).get("deposed")
            if got != expect.get("list"):
                failures.append(f"{tag} (deposed): expected "
                                f"{expect.get('list')!r}, got {got!r}")
        else:
            failures.append(f"{tag}: unknown then-step {sorted(step)}")


def _fold_progress(stderr: str, expect: dict) -> list[str]:
    """Fold an ndjson progress stream and check the stream-level honesty
    contracts (D227): pure JSON, monotone seq from 1, run-start first and
    run-end last, k non-decreasing and reaching n, no event after a terminal.
    The full transition table is pinned in Go; this pins the CLI surface."""
    fails, prev_seq, started, ended = [], 0, False, False
    n, last_k, terminals = None, 0, set()
    TERMINAL = {"done", "failed", "skipped", "indeterminate"}
    lines = [ln for ln in stderr.splitlines() if ln.strip()]
    for ln in lines:
        try:
            ev = json.loads(ln)
        except json.JSONDecodeError:
            return [f"stderr under --progress=ndjson is not pure json: {ln!r}"]
        if ev.get("stream") != "groundhold/progress/v1":
            fails.append(f"bad stream tag: {ev.get('stream')!r}")
        if ev["seq"] <= prev_seq:
            fails.append(f"seq not monotonic: {ev['seq']} after {prev_seq}")
        prev_seq = ev["seq"]
        kind = ev.get("kind")
        if kind == "run-start":
            started, n = True, ev.get("manifest", {}).get("totalActions")
        elif kind == "run-end":
            ended = True
        elif kind in ("transition", "tick"):
            aid = ev.get("actionId")
            if aid in terminals:
                fails.append(f"event after terminal for {aid}")
            if ev.get("k", 0) < last_k:
                fails.append(f"k regressed: {ev.get('k')} < {last_k}")
            last_k = ev.get("k", last_k)
            if kind == "transition" and ev.get("state") in TERMINAL:
                terminals.add(aid)
    if not started:
        fails.append("no run-start")
    if not ended:
        fails.append("no run-end")
    if n is not None and last_k != n:
        fails.append(f"stream ended with k={last_k}, n={n}")
    if "resolved" in expect and n != expect["resolved"]:
        fails.append(f"resolved: expected {expect['resolved']}, got {n}")
    return fails


def run_progress_case_cli(case: dict, impl: list[str]) -> list[str]:
    """D227: apply with --progress=ndjson must emit a well-formed honest stream
    AND leave the machine result (stdout) and the ledger byte-identical to
    --progress=none — progress is a projection, never a source of truth."""
    if not impl:
        return []  # a Go-runtime feature; the library reference has no executor
    expect = case["expect"]
    spec = case["progress"]
    prov = spec.get("provider", "fake")
    at = spec["at"]
    with tempfile.TemporaryDirectory() as td:
        cp = os.path.join(td, "c.yaml")
        kp = os.path.join(td, "k.yaml")
        pp = os.path.join(td, "p.json")
        for path, doc in ((cp, spec["contract"]), (kp, spec["candidate"])):
            with open(path, "w") as f:
                yaml.safe_dump(doc, f)
        comp = subprocess.run(impl + ["plan", cp, kp, "--at", at, "--provider", prov],
                              capture_output=True, text=True)
        if comp.returncode != 0:
            return [f"plan failed: {comp.stderr!r}"]
        with open(pp, "w") as f:
            f.write(comp.stdout)

        def apply(mode: str) -> tuple:
            lp = os.path.join(td, f"l-{mode}.jsonl")
            open(lp, "w").close()
            proc = subprocess.run(
                impl + ["apply", cp, kp, pp, "--ledger", lp, "--at", at,
                        "--provider", prov, "--progress", mode],
                capture_output=True, text=True)
            with open(lp) as f:
                return proc, f.read()

        none_proc, none_led = apply("none")
        nd_proc, nd_led = apply("ndjson")
        fails = []
        for tag, p in (("none", none_proc), ("ndjson", nd_proc)):
            if p.returncode != 0:
                fails.append(f"apply({tag}) rc={p.returncode}: {p.stderr[:200]!r}")
        if none_proc.stdout != nd_proc.stdout:
            fails.append("progress perturbed the machine result (stdout differs across modes)")
        if none_led != nd_led:
            fails.append("progress perturbed the ledger (invariant #6)")
        fails += _fold_progress(nd_proc.stderr, expect)
        return fails


def run_show_case_cli(case: dict, impl: list[str]) -> list[str]:
    """D89 plan preview: `show <plan.json>` renders a saved plan to deterministic
    text. Asserts the render byte-for-byte against a golden, and that no severity
    adjective / composite score ever appears (four-valued discipline on risk).
    A pure function of the plan bytes — Go-runtime, so impl: go."""
    if not impl:
        return []
    spec = case["show"]
    expect = case["expect"]
    base = os.path.dirname(os.path.abspath(__file__))
    plan_path = os.path.join(base, spec["plan"])
    proc = subprocess.run(impl + ["show", plan_path], capture_output=True, text=True)
    if proc.returncode != 0:
        return [f"show rc={proc.returncode}: {proc.stderr[:200]!r}"]
    fails = []
    if "golden" in expect:
        with open(os.path.join(base, expect["golden"])) as f:
            golden = f.read()
        got = proc.stdout
        if expect.get("ignoreHashLine"):
            strip = lambda s: "\n".join(
                ln for ln in s.splitlines() if not ln.startswith("plan sha256:"))
            got, golden = strip(got), strip(golden)
        if got != golden:
            fails.append("render differs from golden (byte-for-byte) -- "
                         "regenerate deliberately if the change is intended")
    for tok in expect.get("absent") or []:
        if tok.lower() in proc.stdout.lower():
            fails.append(f"render contains forbidden token {tok!r} "
                         "(no severity words / composite risk score)")
def run_runs_case_cli(case: dict, impl: list[str]) -> list[str]:
    """D231: `runs --ledger --at` lists every run in a seeded ledger with its
    derived state. Asserts the run count, per-state counts, and the ORDER
    (most-recent-first) at the CLI surface. Go-runtime, impl: go."""
    if not impl:
        return []
    spec = case["runs"]
    expect = case["expect"]
    with tempfile.TemporaryDirectory() as td:
        lp = os.path.join(td, "ledger.jsonl")
        seed_ledger(lp, spec["ledger"])
        # D231: seed detach-registry pointers for launched-but-not-admitted runs,
        # so `runs` can union them in as registry-only/unknown.
        for handle in spec.get("registryHandles") or []:
            rdir = os.path.join(td, ".groundhold", "runs")
            os.makedirs(rdir, exist_ok=True)
            with open(os.path.join(rdir, handle + ".json"), "w") as f:
                json.dump({"handle": handle, "kind": "apply", "ledgerPath": lp,
                           "logPath": os.path.join(rdir, handle + ".log"),
                           "pid": 0, "launchedAt": spec["at"]}, f)
        proc = subprocess.run(impl + ["runs", "--ledger", lp, "--at", spec["at"], "--json"],
                              capture_output=True, text=True)
    if proc.returncode != 0:
        return [f"runs rc={proc.returncode}: {proc.stderr[:200]!r}"]
    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return [f"runs stdout is not json: {e}"]
    fails = []
    if "total" in expect and out.get("total") != expect["total"]:
        fails.append(f"total: expected {expect['total']}, got {out.get('total')}")
    for st, n in (expect.get("byState") or {}).items():
        if (out.get("byState") or {}).get(st) != n:
            fails.append(f"byState[{st}]: expected {n}, got {(out.get('byState') or {}).get(st)}")
    if "order" in expect:
        got = [r["handle"] for r in out.get("runs") or []]
        if got != expect["order"]:
            fails.append(f"order: expected {expect['order']}, got {got}")
    for handle, src in (expect.get("sources") or {}).items():
        r = next((r for r in out.get("runs") or [] if r["handle"] == handle), None)
        if r is None:
            fails.append(f"source: run {handle!r} not listed")
        elif r.get("source") != src:
            fails.append(f"source[{handle}]: expected {src!r}, got {r.get('source')!r}")
    return fails


def run_status_case_cli(case: dict, impl: list[str]) -> list[str]:
    """D229: `status <handle> --ledger --at` derives a background run's state
    purely from seeded ledger events. Asserts the derived state + code (the
    honesty of stalled != failed, running-while-lease-live, etc.) at the CLI
    surface. Go-runtime, impl: go."""
    if not impl:
        return []
    spec = case["status"]
    expect = case["expect"]
    with tempfile.TemporaryDirectory() as td:
        lp = os.path.join(td, "ledger.jsonl")
        seed_ledger(lp, spec["ledger"])
        cmd = impl + ["status", spec["handle"], "--ledger", lp, "--at", spec["at"], "--json"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return [f"status rc={proc.returncode}: {proc.stderr[:200]!r}"]
    try:
        st = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return [f"status stdout is not json: {e}"]
    fails = []
    for k in ("state", "code", "kind"):
        if k in expect and st.get(k) != expect[k]:
            fails.append(f"{k}: expected {expect[k]!r}, got {st.get(k)!r}")
    return fails


def run_apply_case_cli(case: dict, impl: list[str]) -> list[str]:
    expect = case["expect"]
    spec = case["apply"]
    with tempfile.TemporaryDirectory() as td:
        cpath = os.path.join(td, "contract.yaml")
        kpath = os.path.join(td, "candidate.yaml")
        ppath = os.path.join(td, "plan.yaml")
        lpath = os.path.join(td, "ledger.jsonl")
        for path, doc in ((cpath, spec["contract"]),
                          (kpath, spec["candidate"]), (ppath, spec["plan"])):
            with open(path, "w") as f:
                yaml.safe_dump(doc, f)
        if spec.get("ledger"):
            seed_ledger(lpath, spec["ledger"])
        cmd = impl + ["apply", cpath, kpath, ppath, "--ledger", lpath]
        if spec.get("at"):
            cmd += ["--at", spec["at"]]
        for k in spec.get("failKeys") or []:
            cmd += ["--fail-key", k]
        for k in spec.get("unknownKeys") or []:
            cmd += ["--unknown-key", k]
        for k in spec.get("retryableKeys") or []:
            cmd += ["--retryable-key", k]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        deposed_res = deposed_all_res = None
        if "thenDeposed" in expect or "thenDeposedAll" in expect:
            d1 = subprocess.run(impl + ["deposed", "--ledger", lpath],
                                capture_output=True, text=True)
            deposed_res = json.loads(d1.stdout).get("deposed")
            d2 = subprocess.run(impl + ["deposed", "--ledger", lpath, "--all"],
                                capture_output=True, text=True)
            deposed_all_res = json.loads(d2.stdout).get("deposed")
        failures = []
        if "exit" in expect and proc.returncode != expect["exit"]:
            failures.append(f"exit code: expected {expect['exit']}, "
                            f"got {proc.returncode}; stderr: {proc.stderr!r}")
        try:
            res = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            return failures + [f"stdout is not an apply result: {e}"]
        for key in ("status", "events", "bindings", "code"):
            if key in expect and res.get(key) != expect[key]:
                failures.append(f"{key}: expected {expect[key]!r}, "
                                f"got {res.get(key)!r}")
        if "thenDeposed" in expect and deposed_res != expect["thenDeposed"]:
            failures.append(f"deposed: expected {expect['thenDeposed']!r}, "
                            f"got {deposed_res!r}")
        if "thenDeposedAll" in expect and deposed_all_res != expect["thenDeposedAll"]:
            failures.append(f"deposed --all: expected {expect['thenDeposedAll']!r}, "
                            f"got {deposed_all_res!r}")
        run_then_steps(case.get("then") or [], impl, td, cpath, kpath,
                       lpath, failures)
    return failures


def run_ledgerops_case_cli(case: dict, impl: list[str]) -> list[str]:
    """Ledger repair + anchor cases (D69/D70): seed a stitched ledger,
    tamper with it the way real corruption looks (torn write, dropped
    line, pre-D67 fork), and drive repair/anchor against it. The
    fingerprint from the last diagnosis feeds --quarantine; the anchor
    written by the last anchor step feeds --check."""
    spec = case["ledgerops"]
    failures = []
    with tempfile.TemporaryDirectory() as td:
        lpath = os.path.join(td, "ledger.jsonl")
        apath = os.path.join(td, "anchor.json")
        seed_ledger(lpath, spec["ledger"])
        last_fingerprint = ""
        for i, step in enumerate(spec["steps"]):
            expect = step.get("expect") or {}
            if "tamper" in step:
                t = step["tamper"] or {}
                with open(lpath) as f:
                    raw = f.read()
                lines = raw.splitlines(keepends=True)
                if "keepLines" in t:
                    lines = lines[:t["keepLines"]]
                if "dropLine" in t:
                    n = t["dropLine"]
                    lines = lines[:n - 1] + lines[n:]
                if t.get("tearBytes"):
                    joined = "".join(lines)
                    lines = [joined[:len(joined) - t["tearBytes"]]]
                if t.get("reseedEvents") is not None:
                    seed_ledger(lpath, t["reseedEvents"])
                    continue
                with open(lpath, "w") as f:
                    f.write("".join(lines))
                continue
            if "repair" in step:
                s = step["repair"] or {}
                tag = f"step {i} (repair)"
                cmd = impl + ["repair", "--ledger", lpath]
                if s.get("quarantine"):
                    cmd += ["--quarantine"]
                    fp = s.get("fingerprint", "@last")
                    if fp == "@last":
                        fp = last_fingerprint
                    if fp:
                        cmd += ["--fingerprint", fp]
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != expect.get("exit", 0):
                    failures.append(
                        f"{tag} exit: expected {expect.get('exit')}, "
                        f"got {proc.returncode}; stderr: {proc.stderr!r}")
                    continue
                res = json.loads(proc.stdout)
                if res.get("fingerprint"):
                    last_fingerprint = res["fingerprint"]
                if "status" in expect and res.get("status") != expect["status"]:
                    failures.append(f"{tag} status: expected "
                                    f"{expect['status']!r}, "
                                    f"got {res.get('status')!r}")
                if "code" in expect and res.get("code") != expect["code"]:
                    failures.append(f"{tag} code: expected {expect['code']!r},"
                                    f" got {res.get('code')!r}")
                got_kinds = [f["kind"] for f in res.get("findings") or []]
                if "findingKinds" in expect and got_kinds != expect["findingKinds"]:
                    failures.append(f"{tag} findings: expected "
                                    f"{expect['findingKinds']}, got {got_kinds}")
                if "validPrefix" in expect and \
                        res.get("validPrefixLines") != expect["validPrefix"]:
                    failures.append(f"{tag} validPrefixLines: expected "
                                    f"{expect['validPrefix']}, "
                                    f"got {res.get('validPrefixLines')}")
                if "keptLines" in expect and res.get("keptLines") != expect["keptLines"]:
                    failures.append(f"{tag} keptLines: expected "
                                    f"{expect['keptLines']}, "
                                    f"got {res.get('keptLines')}")
                if "detailContains" in expect and not any(
                        expect["detailContains"] in f.get("detail", "")
                        for f in res.get("findings") or []):
                    failures.append(f"{tag} findings: none contain "
                                    f"{expect['detailContains']!r}")
                continue
            if "anchor" in step:
                s = step["anchor"] or {}
                tag = f"step {i} (anchor)"
                cmd = impl + ["anchor", "--ledger", lpath]
                if s.get("check"):
                    cmd += ["--check", apath]
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != expect.get("exit", 0):
                    failures.append(
                        f"{tag} exit: expected {expect.get('exit')}, "
                        f"got {proc.returncode}; stderr: {proc.stderr!r}")
                    continue
                if not s.get("check") and proc.returncode == 0:
                    with open(apath, "w") as f:
                        f.write(proc.stdout)
                res = json.loads(proc.stdout) if proc.stdout.strip() else {}
                for key in ("status", "events"):
                    if key in expect and res.get(key) != expect[key]:
                        failures.append(f"{tag} {key}: expected "
                                        f"{expect[key]!r}, got {res.get(key)!r}")
                continue
            if "replay" in step:
                # `deposed` is the cheapest replay probe: exit 0 iff the
                # ledger folds clean, 5 on corruption
                tag = f"step {i} (replay)"
                proc = subprocess.run(impl + ["deposed", "--ledger", lpath],
                                      capture_output=True, text=True)
                if proc.returncode != expect.get("exit", 0):
                    failures.append(
                        f"{tag} exit: expected {expect.get('exit')}, "
                        f"got {proc.returncode}; stderr: {proc.stderr!r}")
                continue
            failures.append(f"step {i}: unknown ledgerops step "
                            f"{sorted(step)}")
    return failures


def run_converge_case_cli(case: dict, impl: list[str]) -> list[str]:
    """Porcelain cases (D51) run as a SEQUENCE of converge invocations in
    one directory — the second run proving convergence against the ledger
    the first one wrote, instead of hand-forging event hash chains."""
    spec = case["converge"]
    failures = []
    impl_abs = [os.path.abspath(p) if os.path.exists(p) else p for p in impl]
    vocab = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "spec", "vocab"))
    with tempfile.TemporaryDirectory() as td:
        lpath = os.path.join(td, "ledger.jsonl")
        for i, run in enumerate(spec["runs"]):
            cpath = os.path.join(td, f"contract-{i}.yaml")
            kpath = os.path.join(td, f"candidate-{i}.yaml")
            with open(cpath, "w") as f:
                yaml.safe_dump(run.get("contract", spec.get("contract")), f)
            with open(kpath, "w") as f:
                yaml.safe_dump(run.get("candidate", spec.get("candidate")), f)
            cmd = impl_abs + ["converge", cpath, kpath, "--ledger", lpath,
                              "--vocab", vocab, "--json"]
            if run.get("at"):
                cmd += ["--at", run["at"]]
            if run.get("approve"):
                cmd += ["--yes"]
            if run.get("allowDataLoss"):
                cmd += ["--allow-data-loss"]
            if run.get("noReachability"):
                cmd += ["--no-reachability"]
            # Layer 1: drive the reachability probe's HTTPS GET deterministically
            # (no real network) — the same fail-key style the fake provider uses.
            env = dict(os.environ)
            if "reachabilityFake" in run:
                env["GROUNDHOLD_REACHABILITY_FAKE"] = str(run["reachabilityFake"])
            proc = subprocess.run(cmd, capture_output=True, text=True, cwd=td,
                                  env=env)
            expect = run["expect"]
            tag = f"run {i}"
            if proc.returncode != expect["exit"]:
                failures.append(f"{tag} exit: expected {expect['exit']}, "
                                f"got {proc.returncode}; stderr: {proc.stderr!r}")
            if "stderrContains" in expect:
                if expect["stderrContains"] not in proc.stderr:
                    failures.append(f"{tag} stderr: expected "
                                    f"{expect['stderrContains']!r}, "
                                    f"got {proc.stderr!r}")
                continue
            try:
                res = json.loads(proc.stdout)
            except json.JSONDecodeError as e:
                failures.append(f"{tag} stdout is not JSON: {e}")
                continue
            if "status" in expect and res.get("status") != expect["status"]:
                failures.append(f"{tag} status: expected {expect['status']!r}, "
                                f"got {res.get('status')!r}")
            if "code" in expect and res.get("code") != expect["code"]:
                failures.append(f"{tag} code: expected {expect['code']!r}, "
                                f"got {res.get('code')!r}")
            if "phases" in expect and res.get("phases") != expect["phases"]:
                failures.append(f"{tag} phases: expected {expect['phases']}, "
                                f"got {res.get('phases')}")
            if "convergence" in expect and \
                    res.get("convergence") != expect["convergence"]:
                failures.append(f"{tag} convergence: expected "
                                f"{expect['convergence']!r}, "
                                f"got {res.get('convergence')!r}")
            if "reachability" in expect and \
                    res.get("reachability") != expect["reachability"]:
                failures.append(f"{tag} reachability: expected "
                                f"{expect['reachability']!r}, "
                                f"got {res.get('reachability')!r}")
            if "banner" in expect:
                lines_ = [l for l in proc.stderr.splitlines() if l.strip()]
                got = lines_[-1] if lines_ else ""
                if got != expect["banner"]:
                    failures.append(f"{tag} banner: expected "
                                    f"{expect['banner']!r}, got {got!r}")
            if "reasonContains" in expect and not any(
                    expect["reasonContains"] in r
                    for r in res.get("reasons") or []):
                failures.append(f"{tag} reasons: expected one to contain "
                                f"{expect['reasonContains']!r}, "
                                f"got {res.get('reasons')!r}")
    return failures


def run_hints_case_cli(case: dict, impl: list[str]) -> list[str]:
    """State importer cases (D53): write the state file, run hints,
    compare the full mapping — values cross only through the explicit
    allowlist, so the golden pins secrets OUT as much as attributes IN."""
    expect = case["expect"]
    spec = case["hints"]
    with tempfile.TemporaryDirectory() as td:
        spath = os.path.join(td, "state.json")
        with open(spath, "w") as f:
            json.dump(spec["state"], f)
        cmd = impl + ["hints", spath]
        if spec.get("format"):
            cmd += ["--format", spec["format"]]
        proc = subprocess.run(cmd, capture_output=True, text=True)
    failures = []
    if expect.get("error"):
        if proc.returncode != 1:
            failures.append(f"exit: expected 1, got {proc.returncode}")
        if not proc.stderr.startswith("state error:"):
            failures.append(f"stderr: expected 'state error:' prefix, "
                            f"got {proc.stderr!r}")
        return failures
    if proc.returncode != 0:
        return [f"exit: expected 0, got {proc.returncode}; "
                f"stderr: {proc.stderr!r}"]
    try:
        res = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return [f"stdout is not JSON: {e}"]
    if "source" in expect:
        for k, v in expect["source"].items():
            if res.get("source", {}).get(k) != v:
                failures.append(f"source.{k}: expected {v!r}, "
                                f"got {res.get('source', {}).get(k)!r}")
    if "hints" in expect and res.get("hints") != expect["hints"]:
        failures.append(f"hints: expected {expect['hints']!r}, "
                        f"got {res.get('hints')!r}")
    for needle in expect.get("diagnosticsContain") or []:
        if not any(needle in d for d in res.get("diagnostics") or []):
            failures.append(f"diagnostics: expected one to contain "
                            f"{needle!r}, got {res.get('diagnostics')!r}")
    for needle in expect.get("outputNeverContains") or []:
        if needle in proc.stdout:
            failures.append(f"output leaked {needle!r}")
    return failures


SIGNING_CONTRACT = {
    "apiVersion": "contract/v0.1",
    "kind": "InfrastructureContract",
    "meta": {"id": "sig-case", "environment": "test", "version": 1},
    "capabilities": [
        {"id": "db", "type": "capability.database.relational"}],
    "constraints": {"hard": [
        {"id": "c-region", "subject": "db", "path": "location.region",
         "op": "equals", "value": "europe-west1",
         "verify": {"method": "static"}}]},
}


def run_signing_case_cli(case: dict, impl: list[str]) -> list[str]:
    """Event-signature cases (D102): mint a key with `keygen`, drive real
    verbs with --sign-key so the ledger is built the way production
    builds it, then replay/export under --trust. `@pub` in a step's
    trust resolves to the minted public key; a hex literal is used
    verbatim (the foreign-key probes)."""
    spec = case["signing"]
    failures = []
    with tempfile.TemporaryDirectory() as td:
        lpath = os.path.join(td, "ledger.jsonl")
        kpath = os.path.join(td, "key")
        cpath = os.path.join(td, "contract.yaml")
        cappath = os.path.join(td, "capsule.json")
        apath = os.path.join(td, "anchor.json")
        with open(cpath, "w") as f:
            yaml.safe_dump(SIGNING_CONTRACT, f)
        proc = subprocess.run(impl + ["keygen", kpath],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            return [f"keygen failed: {proc.stderr!r}"]
        pub = proc.stdout.strip()
        k2path = os.path.join(td, "key2")
        proc = subprocess.run(impl + ["keygen", k2path],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            return [f"keygen (2) failed: {proc.stderr!r}"]
        pub2 = proc.stdout.strip()
        captured_hash = ""

        def resolve(v):
            if v == "@pub":
                return pub
            if v == "@pub2":
                return pub2
            if v == "@h":
                return captured_hash
            return v

        def trust_flags(s):
            out = []
            t = s.get("trust")
            for one in (t if isinstance(t, list) else [t] if t else []):
                out += ["--trust", resolve(one)]
            if s.get("trustFrom"):
                out += ["--trust-from", resolve(s["trustFrom"])]
            return out
        for i, step in enumerate(spec["steps"]):
            expect = step.get("expect") or {}
            if "publish" in step:
                s = step["publish"] or {}
                tag = f"step {i} (publish)"
                if s.get("version"):
                    doc = dict(SIGNING_CONTRACT)
                    doc["meta"] = dict(doc["meta"], version=s["version"])
                    with open(cpath, "w") as f:
                        yaml.safe_dump(doc, f)
                at = s.get("at") or \
                    f"2026-07-15T08:0{s.get('version', 1) - 1}:00Z"
                cmd = impl + ["publish", cpath, "--ledger", lpath,
                              "--actor", "ops@example.test", "--at", at]
                if s.get("signed", True):
                    cmd += ["--sign-key", k2path if s.get("key") == 2 else kpath]
                cmd += trust_flags(s)
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != expect.get("exit", 0):
                    failures.append(
                        f"{tag} exit: expected {expect.get('exit', 0)}, "
                        f"got {proc.returncode}; stderr: {proc.stderr!r}")
                continue
            if "attest" in step:
                sa = step["attest"] or {}
                tag = f"step {i} (attest)"
                cmd = impl + ["attest", "--ledger", lpath, "--at",
                              sa.get("at", "2026-07-15T12:00:00Z")]
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != expect.get("exit", 0):
                    failures.append(
                        f"{tag} exit: expected {expect.get('exit', 0)}, "
                        f"got {proc.returncode}; stderr: {proc.stderr!r}")
                elif proc.returncode == 0:
                    rep = json.loads(proc.stdout)
                    for path_expr, want in (expect.get("fields") or {}).items():
                        cur = rep
                        for key in path_expr.split("."):
                            cur = cur.get(key) if isinstance(cur, dict) else None
                        if cur != want:
                            failures.append(f"{tag} {path_expr}: expected "
                                            f"{want!r}, got {cur!r}")
                continue
            if "tamperSnapshot" in step:
                import re as _re
                t = step["tamperSnapshot"] or {}
                sp = lpath + ".snapshot"
                with open(sp) as f:
                    raw = f.read()
                if t.get("find"):
                    raw = raw.replace(t["find"], t["replace"])
                elif t.get("findRe"):
                    raw = _re.sub(t["findRe"], t["replaceRe"], raw)
                with open(sp, "w") as f:
                    f.write(raw)
                continue
            if "exportSince" in step:
                sa = step["exportSince"] or {}
                tag = f"step {i} (exportSince)"
                cmd = impl + ["export", "--ledger", lpath,
                              "--since", str(sa["since"])]
                proc = subprocess.run(cmd, capture_output=True, text=True)
                got = len([l for l in proc.stdout.splitlines() if l.strip()])
                if got != sa.get("emits"):
                    failures.append(f"{tag}: expected {sa.get('emits')} "
                                    f"records, got {got}")
                if sa.get("firstIndex") is not None and got > 0:
                    idx = json.loads(proc.stdout.splitlines()[0])["index"]
                    if idx != sa["firstIndex"]:
                        failures.append(f"{tag}: first index {idx}, "
                                        f"expected {sa['firstIndex']}")
                continue
            if "repairProbe" in step:
                tag = f"step {i} (repairProbe)"
                proc = subprocess.run(impl + ["repair", "--ledger", lpath],
                                      capture_output=True, text=True)
                res = json.loads(proc.stdout) if proc.stdout.strip() else {}
                if res.get("status") != (step["repairProbe"] or {}).get("status"):
                    failures.append(f"{tag}: status {res.get('status')!r}, "
                                    f"expected {step['repairProbe'].get('status')!r}")
                continue
            if "snapshot" in step:
                sa = step["snapshot"] or {}
                tag = f"step {i} (snapshot)"
                cmd = impl + ["snapshot", "--ledger", lpath]
                if sa.get("signed"):
                    cmd += ["--sign-key", kpath]
                cmd += trust_flags(sa)
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != expect.get("exit", 0):
                    failures.append(
                        f"{tag} exit: expected {expect.get('exit', 0)}, "
                        f"got {proc.returncode}; stderr: {proc.stderr!r}")
                needle = expect.get("stderrContains")
                if needle and needle not in proc.stderr:
                    failures.append(f"{tag} stderr: expected {needle!r} "
                                    f"in {proc.stderr!r}")
                continue
            if "capsule" in step:
                s = step["capsule"] or {}
                tag = f"step {i} (capsule)"
                cmd = impl + ["capsule", s["capability"], "--ledger", lpath]
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != expect.get("exit", 0):
                    failures.append(
                        f"{tag} exit: expected {expect.get('exit', 0)}, "
                        f"got {proc.returncode}; stderr: {proc.stderr!r}")
                elif proc.returncode == 0:
                    with open(cappath, "w") as f:
                        f.write(proc.stdout)
                continue
            if "tamperCapsule" in step:
                t = step["tamperCapsule"] or {}
                with open(cappath) as f:
                    raw = f.read()
                with open(cappath, "w") as f:
                    f.write(raw.replace(t["find"], t["replace"]))
                continue
            if "anchorEmit" in step:
                sa = step["anchorEmit"] or {}
                cmd = impl + ["anchor", "--ledger", lpath] + trust_flags(sa)
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != expect.get("exit", 0):
                    failures.append(
                        f"step {i} (anchorEmit) exit: expected "
                        f"{expect.get('exit', 0)}, got {proc.returncode}; "
                        f"stderr: {proc.stderr!r}")
                elif proc.returncode == 0:
                    with open(apath, "w") as f:
                        f.write(proc.stdout)
                continue
            if "anchorCheck" in step:
                sa = step["anchorCheck"] or {}
                tag = f"step {i} (anchorCheck)"
                cmd = impl + ["anchor", "--ledger", lpath,
                              "--check", apath] + trust_flags(sa)
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != expect.get("exit", 0):
                    failures.append(
                        f"{tag} exit: expected {expect.get('exit', 0)}, "
                        f"got {proc.returncode}; stderr: {proc.stderr!r}")
                needle = expect.get("stderrContains")
                # the reason rides the JSON on stdout; the banner is on
                # stderr — accept the needle in either channel
                if needle and needle not in proc.stderr \
                        and needle not in proc.stdout:
                    failures.append(f"{tag}: expected {needle!r} in output, "
                                    f"stdout={proc.stdout!r} stderr={proc.stderr!r}")
                continue
            if "writeAnchorBeside" in step:
                with open(apath) as f:
                    raw = f.read()
                with open(lpath + ".anchor", "w") as f:
                    f.write(raw)
                continue
            if "tamperAnchor" in step:
                import re as _re
                t = step["tamperAnchor"] or {}
                with open(apath) as f:
                    raw = f.read()
                with open(apath, "w") as f:
                    f.write(_re.sub(t["findRe"], t["replaceRe"], raw))
                continue
            if "tamperEventSig" in step:
                # flip a hex nibble in an event's sig.sig on line N —
                # the chain stays valid (sig is excluded from the hash),
                # the signature no longer verifies (D139 invalid path)
                n = (step["tamperEventSig"] or {}).get("line", 1)
                with open(lpath) as f:
                    lines = f.read().splitlines()
                doc = json.loads(lines[n - 1])
                sg = doc["sig"]["sig"]
                doc["sig"]["sig"] = ("f" if sg[0] != "f" else "0") + sg[1:]
                lines[n - 1] = json.dumps(doc)
                with open(lpath, "w") as f:
                    f.write("\n".join(lines) + "\n")
                continue
            if "tamperLedgerClaim" in step:
                # zero out the signature's ledger claim on line N —
                # the claim is data; the signed message is not
                n = (step["tamperLedgerClaim"] or {}).get("line", 1)
                with open(lpath) as f:
                    lines = f.read().splitlines()
                doc = json.loads(lines[n - 1])
                doc["sig"]["ledger"] = "sha256:" + "0" * 64
                lines[n - 1] = json.dumps(doc)
                with open(lpath, "w") as f:
                    f.write("\n".join(lines) + "\n")
                continue
            if "capsuleVerify" in step:
                s = step["capsuleVerify"] or {}
                tag = f"step {i} (capsuleVerify)"
                cmd = impl + ["capsule", "--verify", cappath]
                cmd += trust_flags(s)
                if s.get("check"):
                    cmd += ["--check", apath]
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != expect.get("exit", 0):
                    failures.append(
                        f"{tag} exit: expected {expect.get('exit', 0)}, "
                        f"got {proc.returncode}; stderr: {proc.stderr!r}")
                needle = expect.get("stderrContains")
                if needle and needle not in proc.stderr:
                    failures.append(
                        f"{tag} stderr: expected {needle!r} in "
                        f"{proc.stderr!r}")
                continue
            if "tamper" in step:
                t = step["tamper"] or {}
                with open(lpath) as f:
                    raw = f.read()
                raw = raw.replace(t["find"], t["replace"])
                with open(lpath, "w") as f:
                    f.write(raw)
                continue
            if "dropLine" in step:
                # remove line N (1-indexed) — the remaining lines still
                # chain individually but the ledger no longer folds
                n = (step["dropLine"] or {}).get("line", 1)
                with open(lpath) as f:
                    lines = f.read().splitlines()
                del lines[n - 1]
                with open(lpath, "w") as f:
                    f.write("\n".join(lines) + "\n")
                continue
            if "reorderTail" in step:
                # swap the last two lines — each signature stays valid
                with open(lpath) as f:
                    lines = f.read().splitlines()
                lines[-1], lines[-2] = lines[-2], lines[-1]
                with open(lpath, "w") as f:
                    f.write("\n".join(lines) + "\n")
                continue
            if "stripSig" in step:
                with open(lpath) as f:
                    lines = f.read().splitlines()
                out = []
                for line in lines:
                    doc = json.loads(line)
                    doc.pop("sig", None)
                    out.append(json.dumps(doc))
                with open(lpath, "w") as f:
                    f.write("\n".join(out) + "\n")
                continue
            if "captureHash" in step:
                # export without trust: harvest the id (canonical hash)
                # of the event at the given index — the receiver's
                # out-of-band boundary knowledge, simulated
                idx = (step["captureHash"] or {}).get("index", 0)
                proc = subprocess.run(impl + ["export", "--ledger", lpath],
                                      capture_output=True, text=True)
                lines = proc.stdout.strip().splitlines()
                captured_hash = json.loads(lines[idx])["id"]
                continue
            if "replay" in step or "export" in step:
                verb = "replay" if "replay" in step else "export"
                s = step[verb] or {}
                tag = f"step {i} ({verb})"
                # `deposed` is the cheapest full-replay probe; export is
                # the fold-without-replay handover surface — both must
                # enforce --trust identically
                cmd = impl + (["deposed"] if verb == "replay"
                              else ["export"]) + ["--ledger", lpath]
                cmd += trust_flags(s)
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != expect.get("exit", 0):
                    failures.append(
                        f"{tag} exit: expected {expect.get('exit', 0)}, "
                        f"got {proc.returncode}; stderr: {proc.stderr!r}")
                needle = expect.get("stderrContains")
                if needle and needle not in proc.stderr:
                    failures.append(
                        f"{tag} stderr: expected {needle!r} in "
                        f"{proc.stderr!r}")
                continue
            failures.append(f"step {i}: unknown signing step {sorted(step)}")
    return failures


def run_survey_case_cli(case: dict, impl: list[str]) -> list[str]:
    """Code-survey coverage cases (D93): write the contract and the
    survey documents, run `survey`, compare coverage/orphan statuses —
    absence of evidence is never drift unless --complete."""
    spec = case["survey"]
    expect = case["expect"]
    with tempfile.TemporaryDirectory() as td:
        cpath = os.path.join(td, "contract.yaml")
        with open(cpath, "w") as f:
            yaml.safe_dump(spec["contract"], f)
        cmd = impl + ["survey", cpath]
        for i, sdoc in enumerate(spec.get("surveys") or []):
            spath = os.path.join(td, f"s{i}.json")
            with open(spath, "w") as f:
                json.dump(sdoc, f)
            cmd += ["--survey", spath]
        if spec.get("complete"):
            cmd += ["--complete"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
    failures = []
    if expect.get("error"):
        if proc.returncode != 1:
            failures.append(f"exit: expected 1, got {proc.returncode}")
        if not proc.stderr.startswith("survey error:"):
            failures.append(f"stderr: expected 'survey error:' prefix, "
                            f"got {proc.stderr!r}")
        return failures
    if proc.returncode != expect.get("exit", 0):
        failures.append(f"exit: expected {expect.get('exit', 0)}, got "
                        f"{proc.returncode}; stderr: {proc.stderr!r}")
    try:
        res = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return failures + [f"stdout is not JSON: {e}"]
    if "code" in expect and res.get("code") != expect["code"]:
        failures.append(f"code: expected {expect['code']!r}, "
                        f"got {res.get('code')!r}")
    got_cov = {c["dependency"]: c["status"]
               for c in res.get("coverage") or []}
    for dep, status in (expect.get("coverage") or {}).items():
        if got_cov.get(dep) != status:
            failures.append(f"coverage[{dep}]: expected {status!r}, "
                            f"got {got_cov.get(dep)!r}")
    got_orp = {o["capability"]: o["status"]
               for o in res.get("orphans") or []}
    exp_orp = expect.get("orphans")
    if exp_orp is not None:
        if got_orp != exp_orp:
            failures.append(f"orphans: expected {exp_orp!r}, got {got_orp!r}")
    return failures


def run_onboard_case_cli(case: dict, impl: list[str]) -> list[str]:
    """Brownfield onboarding cases (D52): a SEQUENCE of steps
    (discover / adopt / unadopt / converge) sharing one directory and
    one ledger — later steps prove what earlier steps wrote."""
    spec = case["onboard"]
    failures = []
    impl_abs = [os.path.abspath(p) if os.path.exists(p) else p for p in impl]
    vocab = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "spec", "vocab"))
    with tempfile.TemporaryDirectory() as td:
        lpath = os.path.join(td, "ledger.jsonl")
        dpath = os.path.join(td, "discovery.json")
        plan_path = os.path.join(td, "plan.json")

        def keys_from_plan(action_ids):
            if not action_ids:
                return []
            with open(plan_path) as f:
                plan = json.load(f)["plan"]
            by_id = {a["id"]: a for a in plan.get("actions") or []}
            return [by_id[a]["idempotencyKey"] for a in action_ids]

        for i, step in enumerate(spec["steps"]):
            cmd_name = step["cmd"]
            tag = f"step {i} ({cmd_name})"
            cpath = os.path.join(td, f"contract-{i}.yaml")
            kpath = os.path.join(td, f"candidate-{i}.yaml")
            with open(cpath, "w") as f:
                yaml.safe_dump(step.get("contract", spec.get("contract")), f)
            with open(kpath, "w") as f:
                yaml.safe_dump(step.get("candidate", spec.get("candidate")), f)
            if cmd_name == "discover":
                cmd = impl_abs + ["discover", "--at", step["at"]]
            elif cmd_name == "adopt":
                cmd = impl_abs + ["adopt", cpath, kpath, "--ledger", lpath,
                                  "--vocab", vocab, "--at", step["at"]]
                for c, pid in (step.get("map") or {}).items():
                    cmd += ["--map", f"{c}={pid}"]
                if step.get("citeDiscovery"):
                    cmd += ["--discovery", dpath]
            elif cmd_name == "unadopt":
                cmd = impl_abs + ["unadopt", cpath, step["capability"],
                                  "--ledger", lpath, "--at", step["at"]]
            elif cmd_name == "converge":
                cmd = impl_abs + ["converge", cpath, kpath,
                                  "--ledger", lpath, "--vocab", vocab,
                                  "--json", "--yes", "--at", step["at"]]
            elif cmd_name == "observe":
                cmd = impl_abs + ["observe", "--ledger", lpath,
                                  "--at", step["at"], "--record"]
            elif cmd_name == "plan":
                cmd = impl_abs + ["plan", cpath, kpath, "--vocab", vocab,
                                  "--ledger", lpath, "--at", step["at"]]
            elif cmd_name == "apply":
                cmd = impl_abs + ["apply", cpath, kpath, plan_path,
                                  "--ledger", lpath, "--vocab", vocab,
                                  "--at", step["at"]]
                for k in keys_from_plan(step.get("unknownKeysFromPlan") or []):
                    cmd += ["--unknown-key", k]
                for k in keys_from_plan(step.get("failKeysFromPlan") or []):
                    cmd += ["--fail-key", k]
            elif cmd_name == "probe":
                cmd = impl_abs + ["probe", cpath, "--ledger", lpath,
                                  "--at", step["at"], "--record"]
                if step.get("allowIntrusive"):
                    cmd += ["--allow-intrusive"]
                if step.get("capability"):
                    cmd += ["--capability", step["capability"]]
                for k in step.get("failKeys") or []:
                    cmd += ["--fail-key", k]
            elif cmd_name == "resume":
                cmd = impl_abs + ["resume", cpath, "--ledger", lpath,
                                  "--at", step["at"]]
                for k in keys_from_plan(step.get("unknownKeysFromPlan") or []):
                    cmd += ["--unknown-key", k]
            elif cmd_name == "publish":
                cmd = impl_abs + ["publish", cpath, "--ledger", lpath,
                                  "--at", step["at"]]
                if step.get("actor"):
                    cmd += ["--actor", step["actor"]]
            elif cmd_name == "audit":
                cmd = impl_abs + ["audit", cpath, "--ledger", lpath]
                if not step.get("omitAt"):
                    cmd += ["--at", step["at"]]
                if step.get("record"):
                    cmd += ["--record"]
            elif cmd_name == "export":
                cmd = impl_abs + ["export", "--ledger", lpath]
                for t in step.get("types") or []:
                    cmd += ["--type", t]
                if step.get("format"):
                    cmd += ["--format", step["format"]]
                if "since" in step:
                    cmd += ["--since", str(step["since"])]
            else:
                failures.append(f"{tag}: unknown step cmd")
                continue
            proc = subprocess.run(cmd, capture_output=True, text=True, cwd=td)
            if cmd_name == "discover" and proc.returncode == 0:
                with open(dpath, "w") as f:
                    f.write(proc.stdout)
            if cmd_name == "plan" and proc.returncode == 0:
                with open(plan_path, "w") as f:
                    f.write(proc.stdout)
            expect = step["expect"]
            if proc.returncode != expect["exit"]:
                failures.append(f"{tag} exit: expected {expect['exit']}, "
                                f"got {proc.returncode}; stderr: {proc.stderr!r}")
            if cmd_name == "export":
                # NDJSON stream: one record per line
                lines = [json.loads(l) for l in
                         proc.stdout.splitlines() if l.strip()]
                if "eventTypes" in expect:
                    got = [r.get("type") for r in lines]
                    if got != expect["eventTypes"]:
                        failures.append(f"{tag} eventTypes: expected "
                                        f"{expect['eventTypes']}, got {got}")
                ids = [r.get("id") for r in lines]
                if len(set(ids)) != len(ids) or not all(
                        str(i).startswith("sha256:") for i in ids):
                    failures.append(f"{tag}: ids must be unique sha256 "
                                    f"hashes, got {ids}")
                continue
            if "stderrContains" in expect:
                if expect["stderrContains"] not in proc.stderr:
                    failures.append(f"{tag} stderr: expected "
                                    f"{expect['stderrContains']!r}, "
                                    f"got {proc.stderr!r}")
                continue
            try:
                res = json.loads(proc.stdout)
            except json.JSONDecodeError as e:
                failures.append(f"{tag} stdout is not JSON: {e}")
                continue
            for key in ("status", "discoveryHash", "bindings", "events",
                        "violations", "verdicts", "measurements",
                        "failures", "code"):
                if key in expect and res.get(key) != expect[key]:
                    failures.append(f"{tag} {key}: expected {expect[key]!r}, "
                                    f"got {res.get(key)!r}")
            if "reasonContains" in expect:
                pool = list(res.get("reasons") or []) + [
                    v.get("reason", "") for v in res.get("verdicts") or []]
                if not any(expect["reasonContains"] in r for r in pool):
                    failures.append(f"{tag} reasons: expected one to contain "
                                    f"{expect['reasonContains']!r}, "
                                    f"got {pool!r}")
    return failures


def run_observe_case_cli(case: dict, impl: list[str]) -> list[str]:
    expect = case["expect"]
    spec = case["observe"]
    with tempfile.TemporaryDirectory() as td:
        if "ledger" in spec:
            lpath = os.path.join(td, "ledger.jsonl")
            seed_ledger(lpath, spec["ledger"])
            cmd = impl + ["observe", "--ledger", lpath,
                          "--provider", spec.get("provider", "fake")]
        else:
            bpath = os.path.join(td, "bindings.yaml")
            with open(bpath, "w") as f:
                yaml.safe_dump(spec["bindings"], f)
            cmd = impl + ["observe", "--bindings", bpath,
                          "--provider", spec.get("provider", "fake")]
        if spec.get("at"):
            cmd += ["--at", spec["at"]]
        if spec.get("ttl"):
            cmd += ["--ttl", str(spec["ttl"])]
        if spec.get("record"):
            cmd += ["--record"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        appended = None
        if "ledger" in spec and spec.get("record"):
            with open(lpath) as f:
                lines = [json.loads(x) for x in f if x.strip()]
            if lines:
                appended = lines[-1]
    if proc.returncode != 0:
        return [f"exit code: expected 0, got {proc.returncode}; "
                f"stderr: {proc.stderr!r}"]
    try:
        res = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return [f"stdout is not an observe result: {e}"]
    failures = []
    if res.get("observations") != expect.get("observations"):
        failures.append(f"observations: expected {expect.get('observations')!r}, "
                        f"got {res.get('observations')!r}")
    if "partial" in expect and bool(res.get("partial")) != expect["partial"]:
        failures.append(f"partial: expected {expect['partial']!r}, got {res.get('partial')!r}")
    if "unreadable" in expect:
        # pin the capability set only — reason strings are free diagnostic text
        # (request ids / HTTP status), never a stable expectation (D242).
        got_caps = sorted((u or {}).get("capability") for u in (res.get("unreadable") or []))
        if got_caps != sorted(expect["unreadable"]):
            failures.append(f"unreadable capabilities: expected {sorted(expect['unreadable'])!r}, "
                            f"got {got_caps!r}")
    if "appendedEnvironment" in expect:
        got = (appended or {}).get("event", {}).get("environment")
        if got != expect["appendedEnvironment"]:
            failures.append(f"appended event environment: expected "
                            f"{expect['appendedEnvironment']!r}, got {got!r}")
    return failures


def run_case_library(case: dict) -> list[str]:
    expect = case["expect"]
    expected_error = expect.get("error")  # contract | candidate | None
    with tempfile.TemporaryDirectory() as td:
        cpath, kpath, vdir = _write_docs(td, case)
        vocabs = load_vocab_dir(vdir) if vdir else None
        try:
            contract = load_contract(cpath)
        except ContractError as e:
            if expected_error == "contract":
                return []
            return [f"unexpected contract load error: {e}"]
        if expected_error == "contract":
            return ["expected contract load error, document loaded"]

        try:
            cand = load_candidate(kpath, contract=contract, vocabs=vocabs)
        except ContractError as e:
            if expected_error == "candidate":
                return []
            return [f"unexpected candidate load error: {e}"]
        if expected_error == "candidate":
            return ["expected candidate load error, document loaded"]

        report = verify(contract, cand, vocabs=vocabs)
    return check_report(report, expect)


def run_case_cli(case: dict, impl: list[str]) -> list[str]:
    expect = case["expect"]
    expected_error = expect.get("error")
    with tempfile.TemporaryDirectory() as td:
        cpath, kpath, vdir = _write_docs(td, case)
        cmd = impl + ["verify", cpath, kpath, "--json"]
        if vdir:
            cmd += ["--vocab", vdir]
        proc = subprocess.run(cmd, capture_output=True, text=True)

    if expected_error:
        failures = []
        if proc.returncode != 1:
            failures.append(f"exit code: expected 1, got {proc.returncode}")
        if not proc.stderr.startswith(f"{expected_error} error:"):
            failures.append(
                f"stderr: expected {expected_error!r} error prefix, "
                f"got {proc.stderr!r}")
        return failures

    if proc.returncode not in (0, 2):
        return [f"exit code: expected 0 or 2, got {proc.returncode}; "
                f"stderr: {proc.stderr!r}"]
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return [f"stdout is not a JSON report: {e}"]
    failures = check_report(report, expect)
    want_code = 0 if expect["executable"] else 2
    if proc.returncode != want_code:
        failures.append(f"exit code: expected {want_code}, got {proc.returncode}")
    return failures



def run_suggest_case_cli(case: dict, impl: list[str]) -> list[str]:
    """Advisor conformance (D203). suggest is Go-runtime (impl: go), advisory
    only — the exit code is asserted INDEPENDENT of how many suggestions were
    found, and each snippet/citation is pinned so the ruleset's determinism is
    the source of truth (invariant #5)."""
    spec = case["suggest"]
    expect = case["expect"]
    with tempfile.TemporaryDirectory() as td:
        cpath = os.path.join(td, "contract.yaml")
        with open(cpath, "w") as fh:
            yaml.safe_dump(spec["contract"], fh)
        vocab = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "spec", "vocab"))
        cmd = impl + ["suggest", cpath, "--vocab", vocab]
        if spec.get("candidate"):
            kpath = os.path.join(td, "candidate.yaml")
            with open(kpath, "w") as fh:
                yaml.safe_dump(spec["candidate"], fh)
            cmd.append(kpath)
        cmd.append("--json")
        if spec.get("as"):
            cmd += ["--as", spec["as"]]
        proc = subprocess.run(cmd, capture_output=True, text=True)
    failures = []
    want_exit = expect.get("exit", 0)
    if proc.returncode != want_exit:
        failures.append(f"exit code: expected {want_exit}, got {proc.returncode}; "
                        f"stderr: {proc.stderr!r}")
        return failures
    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return [f"stdout is not JSON: {e}"]
    if out.get("specVersion") != "contract/v0.1":
        failures.append(f"specVersion: expected contract/v0.1, got {out.get('specVersion')!r}")
    for key in ("suggested", "alreadyEnforced"):
        if key in expect and out.get(key) != expect[key]:
            failures.append(f"{key}: expected {expect[key]}, got {out.get(key)}")
    got = out.get("suggestions") or []
    by_key = {(g.get("capability"), g.get("path")): g for g in got}
    # order is asserted separately so a re-sort is caught
    if "order" in expect:
        order = [(g.get("capability"), g.get("path")) for g in got]
        want_order = [tuple(x) for x in expect["order"]]
        if order != want_order:
            failures.append(f"order: expected {want_order}, got {order}")
    for want in expect.get("suggestions", []):
        k = (want["capability"], want["path"])
        g = by_key.get(k)
        if g is None:
            failures.append(f"missing suggestion {k}")
            continue
        for field in ("op", "value", "scope", "ruleId", "rationale", "snippet"):
            if field in want and g.get(field) != want[field]:
                failures.append(f"{k}.{field}: expected {want[field]!r}, got {g.get(field)!r}")
        if "controls" in want and g.get("controls") != want["controls"]:
            failures.append(f"{k}.controls: expected {want['controls']}, got {g.get('controls')}")
    for k in expect.get("absent", []):
        if tuple(k) in by_key:
            failures.append(f"unexpected suggestion present: {tuple(k)}")
    return failures


def dispatch_case(case: dict, impl) -> list[str]:
    """Run one case through the runner its shape selects, returning its
    failures. Pure w.r.t. process state — every runner isolates in its own
    TemporaryDirectory + subprocess, so a case is a self-contained unit of
    work (this is what lets the CLI modes run concurrently, see main)."""
    if "plan" in case:
        return run_plan_case_cli(case, impl)
    elif "observe" in case:
        return run_observe_case_cli(case, impl)
    elif "apply" in case:
        return run_apply_case_cli(case, impl)
    elif "progress" in case:
        return run_progress_case_cli(case, impl)
    elif "show" in case:
        return run_show_case_cli(case, impl)
    elif "runs" in case:
        return run_runs_case_cli(case, impl)
    elif "status" in case:
        return run_status_case_cli(case, impl)
    elif "ledgerops" in case:
        return run_ledgerops_case_cli(case, impl)
    elif "converge" in case:
        return run_converge_case_cli(case, impl)
    elif "onboard" in case:
        return run_onboard_case_cli(case, impl)
    elif "hints" in case:
        return run_hints_case_cli(case, impl)
    elif "signing" in case:
        return run_signing_case_cli(case, impl)
    elif "survey" in case:
        return run_survey_case_cli(case, impl)
    elif "forecast" in case:
        return run_forecast_case_cli(case, impl)
    elif "suggest" in case:
        return run_suggest_case_cli(case, impl)
    elif "scenario" in case:
        return (run_scenario_case_cli(case, impl) if impl
                else run_scenario_case_library(case))
    elif "document" in case:
        return (run_hash_case_cli(case, impl) if impl
                else run_hash_case_library(case))
    else:
        return run_case_cli(case, impl) if impl else run_case_library(case)


def main() -> int:
    argv = sys.argv[1:]
    impl = None
    if "--impl" in argv:
        i = argv.index("--impl")
        if i + 1 >= len(argv):
            print("--impl requires a command string", file=sys.stderr)
            return 1
        impl = shlex.split(argv[i + 1])

    is_go = impl is not None and any("groundhold-go" in part for part in impl)

    # Collect the work-list first (deterministic file+case order), separating
    # skips from cases to run. Each case is independent (own tempdir/subprocess),
    # so the CLI modes fan out over a thread pool — the wall-clock cost is
    # subprocess-bound, and 200+ sequential subprocesses dominated the gate.
    work, skipped = [], 0
    for path in sorted(glob.glob(os.path.join(os.path.dirname(__file__), "cases", "*.yaml"))):
        with open(path) as f:
            doc = yaml.safe_load(f)
        for case in doc.get("cases", []):
            # cases for components that exist in one implementation only
            # (D24: compiler onward is Go-only)
            if case.get("impl") == "go" and not is_go:
                skipped += 1
                continue
            work.append(case)

    # GROUNDHOLD_JOBS overrides the worker count (=1 forces sequential, the audit
    # path for any suspected ordering effect). The library mode stays sequential
    # (in-process, already sub-second — no subprocess isolation to lean on).
    env_jobs = os.environ.get("GROUNDHOLD_JOBS")
    if env_jobs:
        jobs = max(1, int(env_jobs))
    else:
        jobs = min(16, (os.cpu_count() or 1)) if impl else 1

    results: dict[str, list[str]] = {}
    if jobs > 1 and len(work) > 1:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=jobs) as ex:
            futs = {ex.submit(dispatch_case, c, impl): c["name"] for c in work}
            for fut, name in futs.items():
                results[name] = fut.result()
    else:
        for c in work:
            results[c["name"]] = dispatch_case(c, impl)

    # Print in a stable order (case name) so the log is reproducible regardless
    # of completion order — the tally is order-independent by construction.
    failed = 0
    for name in sorted(results):
        failures = results[name]
        if failures:
            failed += 1
            print(f"FAIL {name}")
            for msg in failures:
                print(f"     {msg}")
        else:
            print(f"PASS {name}")

    total = len(work)
    mode = f"cli: {' '.join(impl)}" if impl else "library"
    skips = f", {skipped} skipped" if skipped else ""
    print(f"\n{total - failed}/{total} conformance cases passed ({mode}{skips})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
