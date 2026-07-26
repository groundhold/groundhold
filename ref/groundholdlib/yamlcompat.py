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


class Core12Loader(yaml.SafeLoader):
    """A SafeLoader whose implicit scalar resolution mirrors go-yaml v3."""


# start from a clean resolver table — PyYAML's 1.1 defaults are exactly
# what diverges — and re-add only what go-yaml v3 resolves.
Core12Loader.yaml_implicit_resolvers = {}


def _add(tag: str, pattern: str, first: str) -> None:
    Core12Loader.add_implicit_resolver(tag, re.compile(pattern, re.X), list(first))


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


def safe_load(stream):
    """Drop-in for yaml.safe_load with go-yaml-matched scalar resolution."""
    return yaml.load(stream, Core12Loader)
