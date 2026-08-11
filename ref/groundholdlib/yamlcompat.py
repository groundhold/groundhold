"""YAML scalar resolution matched to the Go runtime (gopkg.in/yaml.v3).

Identity is the sha256 of the canonical JSON of the PARSED model (D34/
D35), so the two implementations must resolve the same source scalar to
the same typed value or their hashes diverge — breaking byte-identical
identity, and with it every D102 signature and D103 capsule computed by
one tool and verified by the other.

PyYAML defaults to YAML 1.1: it resolves yes/no/on/off as booleans and
12:30:00 as a sexagesimal int, where go-yaml v3 (YAML 1.2 core, plus a
couple of its own quirks) keeps them as strings and reads 1e3 as a
float. `Core12Loader` overrides the implicit resolvers to match go-yaml
v3 EXACTLY (verified token-by-token against the runtime), so a document
hashes identically in both. Pinned by dual hash cases; the differential
harness generates these once-blind tokens (review fix).
"""
from __future__ import annotations
import re

import yaml

# Imported lazily inside the module to keep the dependency one-way: contract.py imports
# this module, so this module cannot import it at load time.
def _ContractError(msg: str) -> Exception:
    from .contract import ContractError
    return ContractError(msg)



class Core12Loader(yaml.SafeLoader):
    """A SafeLoader whose implicit scalar resolution mirrors go-yaml v3."""


# start from a clean resolver table — PyYAML's 1.1 defaults are exactly
# what diverges — and re-add only what go-yaml v3 resolves.
Core12Loader.yaml_implicit_resolvers = {}


def _add(tag: str, pattern: str, first: str) -> None:
    # D608: PyYAML dispatches an EMPTY scalar on the key "" — `resolvers.get("")` —
    # so a resolver that should fire on `note:` with no value must list the empty
    # string among its first characters. This helper split a plain string, and the
    # null registration wrote "\0" (NUL) where it meant "" (empty). The resolver
    # never fired, an empty scalar fell through to str, and the reference read `""`
    # where go-yaml reads `null` — the same bytes with two document identities.
    chars = [c for c in first if c != "\0"]
    if "\0" in first:
        chars.append("")
    Core12Loader.add_implicit_resolver(tag, re.compile(pattern, re.X), chars)


# bool: ONLY true/false variants (go-yaml does NOT treat yes/no/on/off
# or y/n as booleans — those stay strings)
_add("tag:yaml.org,2002:bool", r"^(?:true|True|TRUE|false|False|FALSE)$", "tTfF")

# null: null / ~ / empty
_add("tag:yaml.org,2002:null", r"^(?:~|null|Null|NULL|)$", "~nN\0")

# int: binary, octal (BOTH 0o-prefixed AND leading-zero — go reads 010
# as octal 8), decimal, hex; NO sexagesimal (12:30:00 stays a string)
_add(
    "tag:yaml.org,2002:int",
    r"""^(?:[-+]?0b[0-1_]+
         |[-+]?0o?[0-7_]+
         |[-+]?(?:0|[1-9][0-9_]*)
         |[-+]?0x[0-9a-fA-F_]+)$""",
    "-+0123456789",
)

# timestamp: go-yaml v3 resolves an unquoted date or RFC3339 datetime to
# time.Time, and the runtime's canonicalizer then refuses it ("YAML timestamps are
# not canonicalizable in v1", spec/canonicalization.md). D685: this table had no
# timestamp resolver, so the reference kept the scalar as a STRING — a document the
# runtime REFUSES took the identity of the correctly quoted one, and state.py's own
# `occurredAt must be a quoted RFC3339 string` guard was unreachable code, since its
# loader could never produce a non-string. The module's docstring claims this table
# mirrors go-yaml "EXACTLY (verified token-by-token)"; this is the token it missed.
#
# PyYAML's SafeConstructor already builds date/datetime for this tag, so resolving
# it is enough: the value stops being a str, the guard fires, and canon() refuses it
# with the same "cannot canonicalize value of type …" the runtime gives.
_add(
    "tag:yaml.org,2002:timestamp",
    r"""^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]
         |[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?
          (?:[Tt]|[ \t]+)[0-9][0-9]?
          :[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?
          (?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$""",
    "0123456789",
)

# float: fixed or exponent form (1e3 is a float in go, unlike PyYAML),
# plus inf/nan; NO sexagesimal
_add(
    "tag:yaml.org,2002:float",
    r"""^(?:[-+]?(?:\.[0-9]+|[0-9](?:[0-9_]*[0-9])?(?:\.[0-9_]*)?)
             (?:[eE][-+]?[0-9]+)?
         |[-+]?\.(?:inf|Inf|INF)
         |\.(?:nan|NaN|NAN))$""",
    "-+0123456789.",
)


# merge key: go-yaml v3 EXPANDS `<<` into the mapping. Clearing the resolver table
# removed this tag with the rest, so PyYAML's flatten_mapping never fired and `<<`
# survived as a literal key — the same document with two identities (D609).
_add("tag:yaml.org,2002:merge", r"^(?:<<)$", "<")


def _no_duplicate_keys(loader, node, deep=False):
    """Refuse a mapping that defines the same key twice (D609).

    go-yaml refuses it outright — `mapping key "dup" already defined at line 10` —
    while PyYAML silently keeps the last one. A document one implementation reads and
    the other rejects breaks the dual guarantee as surely as a hash divergence does,
    and the ambiguous half is the one that answers. Which of the two values the author
    meant is not knowable, so neither is guessed.
    """
    loader.flatten_mapping(node)
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            hashable = key in seen
        except TypeError:  # unhashable key — the canonicalizer refuses it later
            continue
        if hashable:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark,
                f'mapping key {key!r} already defined', key_node.start_mark)
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


Core12Loader.add_constructor(
    "tag:yaml.org,2002:map", lambda l, n: _no_duplicate_keys(l, n))


def safe_load(stream):
    """Drop-in for yaml.safe_load with go-yaml-matched scalar resolution.

    D609: a parse failure leaves here as a ContractError, never as a traceback. Every
    caller already handles ContractError and reports it in the error protocol the spec
    defines (`document error: …`, exit 1); PyYAML's own exceptions are not in that
    family, so a duplicate key, a custom tag, a second `---` document or nesting deep
    enough to blow the recursion limit printed a Python stack trace where the runtime
    prints one line. A tool that crashes instead of refusing has still refused — but it
    has told a machine reader nothing it can act on.
    """
    try:
        return yaml.load(stream, Core12Loader)
    except RecursionError:
        raise _ContractError(
            "document nests too deeply to parse") from None
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None) or getattr(e, "context_mark", None)
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        problem = getattr(e, "problem", None) or str(e).splitlines()[0]
        raise _ContractError(f"{problem}{where}") from None
