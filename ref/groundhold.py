#!/usr/bin/env python3
"""groundhold — reference implementation of the Infrastructure Contract spec v0.1.

Usage:
  groundhold.py validate <contract.yaml>
  groundhold.py verify   <contract.yaml> <candidate.yaml> [--json] [--vocab <dir>]
  groundhold.py hash     <document.yaml>
  groundhold.py scenario <scenario.yaml>

Exit codes:
  0  ok / executable
  1  structural error in a document
  2  candidate is not executable against the contract
"""
import json
import sys


from groundholdlib import canonical, render, yamlcompat
from groundholdlib.contract import load_contract, load_candidate, ContractError
from groundholdlib.plan import load_plan
from groundholdlib.scenario import run_scenario
from groundholdlib.state import load_event
from groundholdlib.verify import verify
from groundholdlib.vocab import load_vocab_dir


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 1
    cmd = argv[1]

    if cmd == "hash":
        # D34: identity of the semantic model, kind-detected from the doc
        try:
            # D608: yamlcompat, not yaml.safe_load. PyYAML resolves YAML 1.1; the
            # whole point of yamlcompat is to resolve scalars the way go-yaml does.
            # These two call sites used the 1.1 loader, so a DiscoveryDocument (hashed
            # straight from this dict) and every scenario document were read by a
            # DIFFERENT loader than the four kinds around them: `note: yes` hashed as
            # a bool here and a string in the runtime, and a scenario step keyed
            # `yes:` resolved to True on one side and "yes" on the other, giving
            # stale-vs-fresh from the same file.
            with open(argv[2]) as f:
                doc = yamlcompat.safe_load(f)
            kind = doc.get("kind") if isinstance(doc, dict) else None
            if kind == "InfrastructureContract":
                print(canonical.hash_contract(load_contract(argv[2])))
            elif kind == "ImplementationCandidate":
                print(canonical.hash_candidate(load_candidate(argv[2])))
            elif kind == "LedgerEvent":
                print(canonical.hash_event(load_event(argv[2])))
            elif kind == "SealedPlan":
                print(canonical.hash_plan(load_plan(argv[2])))
            elif kind == "DiscoveryDocument":
                print(canonical.hash_discovery(doc))
            else:
                print(f"document error: unknown kind {kind!r}", file=sys.stderr)
                return 1
            return 0
        except (ContractError, OSError) as e:
            print(f"document error: {e}", file=sys.stderr)
            return 1

    if cmd == "scenario":
        # D37: deterministic concurrency scenario engine
        try:
            with open(argv[2]) as f:
                doc = yamlcompat.safe_load(f)  # D608: not PyYAML's 1.1 resolution
            results = run_scenario(doc)
        except (ContractError, OSError) as e:
            print(f"scenario error: {e}", file=sys.stderr)
            return 1
        print(json.dumps({"results": results}, indent=2))
        return 0

    vocabs = None
    if "--vocab" in argv:
        i = argv.index("--vocab")
        if i + 1 >= len(argv):
            print("--vocab requires a directory", file=sys.stderr)
            return 1
        try:
            vocabs = load_vocab_dir(argv[i + 1])
        except (ContractError, OSError) as e:
            print(f"vocab error: {e}", file=sys.stderr)
            return 1

    try:
        contract = load_contract(argv[2])
    except (ContractError, OSError) as e:
        print(f"contract error: {e}", file=sys.stderr)
        return 1

    if cmd == "validate":
        print(f"OK  contract {contract.id} v{contract.version}: "
              f"{len(contract.capabilities)} capabilities, "
              f"{len(contract.constraints)} constraints "
              f"({sum(c.severity == 'hard' for c in contract.constraints)} hard)")
        return 0

    if cmd == "verify":
        if len(argv) < 4:
            print(__doc__)
            return 1
        try:
            cand = load_candidate(argv[3], contract=contract, vocabs=vocabs)
        except (ContractError, OSError) as e:
            print(f"candidate error: {e}", file=sys.stderr)
            return 1
        try:
            report = verify(contract, cand, vocabs=vocabs)
        except ContractError as e:
            # the free-form implementation block (D26) is not validated at load,
            # so a value with no canonical form (e.g. a sub-1e-17 float, D179)
            # surfaces here when verify computes the candidate hash — refuse
            # cleanly rather than let it crash; an un-canonicalizable candidate
            # has no identity and cannot be sealed.
            print(f"candidate error: {e}", file=sys.stderr)
            return 1
        if "--json" in argv:
            print(json.dumps(report, indent=2))
            # stdout carried the machine result; the banner goes to the
            # prose channel (D90) with the verdict rollup refining exit 2
            exit_code = 0 if report["executable"] else 2
            hard = [v for v in report["verdicts"] if v["severity"] == "hard"]
            word, sgr = render.pick(
                "verify", exit_code, report.get("code") or "",
                [v["constraint"] for v in hard if v["verdict"] == "violated"],
                [v["constraint"] for v in hard if v["verdict"] == "unknown"],
                [v["constraint"] for v in hard if v["verdict"] == "unverifiable"])
            culprit_ids = ([v["constraint"] for v in hard
                            if v["verdict"] == "violated"] if word == "VIOLATED"
                           else [v["constraint"] for v in hard
                                 if v["verdict"] in ("unknown", "unverifiable")]
                           if word == "BLOCKED" else [])
            culprit = ""
            if culprit_ids:
                culprit = f": {culprit_ids[0]}"
                if len(culprit_ids) > 1:
                    culprit += f" (+{len(culprit_ids) - 1} more)"
            emode = render.detect("auto", False, sys.stderr)
            print(emode.paint(sgr, word) + culprit, file=sys.stderr)
            return exit_code

        # Human rendering per spec/presentation.md (D89): shape-first
        # glyphs, provenance as brightness, the vocabulary joined at
        # friction only, the banner — never alone — last.
        color_flag = "auto"
        if "--color" in argv:
            i = argv.index("--color")
            if i + 1 >= len(argv):
                print("--color requires auto|never|always", file=sys.stderr)
                return 1
            color_flag = argv[i + 1]
        mode = render.detect(color_flag, "--ascii" in argv)
        by_id = {c.id: c for c in contract.constraints}
        cap_type = {cid: (raw.get("type") or "")
                    for cid, raw in contract.capabilities.items()}
        exit_code = 0 if report["executable"] else 2

        s = report["summary"]
        print(f"contract {report['contract']} v{report['contractVersion']}")
        violated, unknown, unverifiable = [], [], []
        for v in report["verdicts"]:
            glyph = mode.paint(render.verdict_color(v["verdict"]),
                               mode.glyph(v["verdict"]))
            basis = ""
            dim = False
            if v.get("basis") not in (None, "declared"):
                basis = f" [{v['basis']}]"
                dim = True
            line = (f"{v['constraint']:<28} {v['verdict']:<12}"
                    f"{basis}  {v['reason']}")
            print(f"  {glyph} {mode.dim(line) if dim else line}")
            cn = by_id.get(v["constraint"])
            if v["verdict"] != "satisfied" and cn is not None:
                if cn.severity == "hard":
                    {"violated": violated, "unknown": unknown,
                     "unverifiable": unverifiable}.get(
                        v["verdict"], []).append(v["constraint"])
                voc = (vocabs or {}).get(cap_type.get(cn.subject, ""))
                attrs = voc.attributes.get(cn.path) if voc else None
                f = render.friction(cn.path, attrs)
                if f:
                    print(f"      {mode.dim(f)}")

        print(f"\n  {s['satisfied']} satisfied, {s['violated']} violated, "
              f"{s['unknown']} unknown, {s['unverifiable']} unverifiable"
              + (f", {s['verdictsOnAssumedValues']} verdict(s) rest on assumed/inferred values"
                 if s["verdictsOnAssumedValues"] else ""))
        word, sgr = render.pick("verify", exit_code, report.get("code") or "",
                                violated, unknown, unverifiable)
        culprit = ""
        if word == "VIOLATED":
            ids, verdict = violated, "violated"
        elif word == "BLOCKED":
            ids = unknown + unverifiable
            verdict = "unknown" if unknown else "unverifiable"
        else:
            ids = []
        if ids:
            cn = by_id[ids[0]]
            culprit = f": {ids[0]} {verdict} — {cn.path}"
            if verdict == "unknown" and cn.verify_method == "probe":
                culprit += " requires probe verification"
            if len(ids) > 1:
                culprit += f" (+{len(ids) - 1} more)"
        print(f"  {mode.paint(sgr, word)}{culprit}")
        return exit_code

    print(__doc__)
    return 1


def _main_with_banner(argv: list[str]) -> int:
    """The final banner (D90): one word, stderr, only when the verb has
    not already rendered its own. verify renders inline (text) or emits
    it itself (--json, with the verdict rollup); validate's OK line and
    the product stdout of hash/scenario stay banner-free on success."""
    code = main(argv)
    verb = argv[1] if len(argv) > 1 else ""
    if verb and verb != "verify" and code != 0:
        word, sgr = render.pick(verb, code, "", [], [], [])
        mode = render.detect("auto", False, sys.stderr)
        print(mode.paint(sgr, word), file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(_main_with_banner(sys.argv))
