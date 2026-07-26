"""Presentation layer (D89, spec/presentation.md): the closed banner
vocabulary, shape-first verdict glyphs and the color discipline.
Nothing here is a machine interface — machines route on exit codes and
JSON `code` fields, never on banners or glyphs. Deterministic, like
everything in this package."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

_GLYPHS = {"satisfied": "✓", "violated": "✗",
           "unknown": "?", "unverifiable": "∅"}
# Pinned fallback set: NA, never "-" (reads as skipped/neutral).
_ASCII = {"satisfied": "OK", "violated": "X",
          "unknown": "?", "unverifiable": "NA"}
# Closed palette (SGR parameters): nothing else, no shades.
GREEN, RED, YELLOW, BLUE, MAGENTA = "32", "31", "33", "34", "35"
RED_INVERSE = "31;7"
_VERDICT_COLOR = {"satisfied": GREEN, "violated": RED,
                  "unknown": YELLOW, "unverifiable": MAGENTA}


@dataclass
class Mode:
    color: bool = False
    ascii: bool = False

    def paint(self, sgr: str, s: str) -> str:
        return f"\033[{sgr}m{s}\033[0m" if self.color else s

    def dim(self, s: str) -> str:
        """Provenance renders as brightness: color says WHAT we know,
        brightness says HOW FIRMLY."""
        return f"\033[2m{s}\033[0m" if self.color else s

    def glyph(self, verdict: str) -> str:
        table = _ASCII if self.ascii else _GLYPHS
        return table.get(verdict, "?")


def verdict_color(verdict: str) -> str:
    return _VERDICT_COLOR.get(verdict, MAGENTA)


def detect(color_flag: str = "auto", ascii_flag: bool = False,
           out=None) -> Mode:
    """Color only on a TTY, NO_COLOR honored, glyphs only under a
    UTF-8 locale."""
    out = out or sys.stdout
    if color_flag == "always":
        color = True
    elif color_flag == "never":
        color = False
    else:
        color = (getattr(out, "isatty", lambda: False)()
                 and not os.environ.get("NO_COLOR")
                 and os.environ.get("TERM") != "dumb")
    ascii_ = ascii_flag or not _utf8_locale()
    return Mode(color=color, ascii=ascii_)


def _utf8_locale() -> bool:
    for k in ("LC_ALL", "LC_CTYPE", "LANG"):
        v = os.environ.get(k)
        if v:
            return "UTF-8" in v.upper() or "UTF8" in v.upper()
    return False


def pick(verb: str, exit_code: int, code: str,
         violated: list, unknown: list, unverifiable: list):
    """Banner selection by (exit, code, rollup) precedence: corruption >
    death > staleness > invalid > proven falsehood > missing knowledge >
    refusal > success. A refusal is never a failure."""
    if exit_code == 5:
        return "CORRUPTED", RED_INVERSE
    if exit_code == 4:
        return "DIED", RED
    if exit_code == 3:
        return "STALE", YELLOW
    if exit_code == 1:
        return "INVALID", RED
    if violated:
        return "VIOLATED", RED
    if unknown or unverifiable:
        return "BLOCKED", YELLOW
    if exit_code == 2:
        return ("REFUSED " + code if code else "REFUSED"), BLUE
    # green ONLY on exit 0 (D194): an unenumerated nonzero is not success.
    if exit_code != 0:
        return "FAILED", RED
    return _green_word(verb), GREEN


# _green_word mirrors the Go greenWord (render.go) EXACTLY, so the two
# implementations agree on every (verb, 0) banner — apply's executional
# success (APPLIED) is never labelled with verify's epistemic claim (PROVEN).
def _green_word(verb: str) -> str:
    return {
        "verify": "PROVEN", "audit": "PROVEN",
        "converge": "CONVERGED", "apply": "APPLIED", "plan": "SEALED",
    }.get(verb, "OK")


def friction(path: str | None, attrs: dict | None) -> str:
    """The teaching line for a vocabulary path — joined only at the
    moment of friction, never on the happy path."""
    if not path or not attrs:
        return ""
    desc = attrs.get("description") or ""
    note = attrs.get("verification") or ""
    if not desc and not note:
        return ""
    if not desc:
        return f"{path} — {note}"
    if not note:
        return f"{path} — {desc}"
    return f"{path} — {desc[:1].lower()}{desc[1:]}; {note}"
