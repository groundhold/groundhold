# Six ways our own documentation lied, in one day

Every claim in this project is gated. Numbers in prose are checked against the code
that produces them. Verbs named in documents must exist. Counts in the README are
re-derived from the drivers. There is a gate that fails when a gate finds nothing,
because a check with an empty subject passes forever.

Then someone walked the front door — downloaded a release, followed the README, ran
what the pages said to run — and in one day found six published things that were false.

None of them were caught by any of those gates. They have one property in common, and
it is the point of this note:

> **A published sequence that nothing executes is a claim nobody checked.**

## What was broken

**The sixty-second path required a clone it said you did not need.** The README opened
with "no toolchain, no clone", then gave a command reading `examples/laptop/…` — a file
that exists only in a clone. Followed literally with a downloaded binary it produced
`no such file or directory`, inside the minute the heading promised.

**The tool's own two documents refused each other.** With a working path added, the
scaffold that writes a starter contract and a matching candidate produced a pair the
tool would not accept: the candidate declared the kind default for a boolean, `false`,
against a contract requiring `true`. First run of the first thing a newcomer does.

**A correct fix falsified a document in another file.** The runtime started blocking a
hard constraint it cannot witness — right, and overdue. The scaffolded contract pinned
attributes the built-in demo provider does not witness, so the published path began
ending `BLOCKED`. Nothing connected the two changes; nothing could.

**A verdict line taught the opposite of what the tool prints.** An earlier fix, from
the field, had narrowed a word: `verify` used to render `observed <value>` whatever the
provenance was, so a budget constraint compared a number the author wrote against a
threshold the author wrote and reported `observed 6 EUR` while the bill was 2.4× that.
The runtime was corrected. The two documents a newcomer reads first went on printing
the old sentence for weeks.

**A specification example had been invalid for a month.** A rule landed that an update
carries a reviewed change-set; the shipped example plan carried none, so the tool
refused to load the artefact the specification directory offers as *the example of what
a compiler emits*. Its header told the reader that the hashes it pins are the ones
`groundhold hash` reproduces. Neither did. The document handed the reader the exact
command that exposes it.

**The documentation site served a tree three days old.** The deploy was manual-only,
with a comment explaining why: the repository was private, and Pages needs a public one
on that plan. That stopped being true at launch. So every fix above was merged, gated,
visible in the repository — and absent from the site people are pointed at.

## Why gates did not catch any of it

Look at what each gate asks.

*Does this number match the code?* — checks a number.
*Does this verb exist?* — checks a name.
*Does this file link resolve?* — checks a path.

Every one is a check on a **fragment** of a document. Not one of them runs the
document. And the failures above are not wrong fragments; they are correct fragments in
a sequence that no longer works, or a true sentence falsified by a routine event
somewhere else.

That last part is the sharp edge. Four of the six were **true when written**:

| what published | what falsified it |
|---|---|
| a download line naming an exact release | cutting the next release |
| a verdict example | the runtime correcting a word |
| a starter contract | a safety rule getting stricter |
| a "deploy is manual because we are private" note | going public |

Each event is routine, each was correct, and none of them is connected to the sentence
it broke by anything a reviewer would see in a diff.

## What actually works

One thing, and it is dull: **make the routine event execute the sentence.**

The newcomer path now runs on every check, from an empty directory, with the binary —
scaffold a contract, scaffold a candidate, fill the one blank, converge twice, and the
second run must report converged. It failed the first time it ran, which is how the
third defect above was found, hours after the path went live.

The release workflow now refuses a tag the README's download line does not name. Not a
warning — the release does not publish. It is checkable there and nowhere else: only at
release time is the tag known.

The example harness discovers shipped plans the way it already discovered contracts,
requires each to load, and re-derives the hashes the file claims are reproducible. The
document's claim about itself became a checked property rather than a sentence.

The docs deploy triggers on documentation changes, because the note explaining its
dormancy also contained its own fix — *add a push trigger* — and had been waiting for
somebody to remember that the condition expired.

## The uncomfortable part

We found six because someone finally ran the pages. We do not know the number for
anything nobody has walked yet, and neither do you for yours.

So the useful question is not "are our docs accurate". It is:

**Which published sequences does something execute, and which are only read?**

For the second list, the fix is never proofreading. Proofreading catches a wrong
fragment; it cannot catch a correct fragment in a sequence that stopped working. The
fix is to find the routine event — a release, a deploy, a rule getting stricter — and
make it run the thing that its own success falsifies.

The counter-argument is that this is a lot of machinery for documentation. Two of the
six were on the first page a stranger reads, one of them a security-shaped attribute,
and one shipped in the directory whose entire purpose is to be measured against by
people implementing the specification independently. Documentation is where a system
makes its promises. It is not obvious why it should be the only surface nothing runs.

---

*The six are recorded in full, with the code and the reasoning, in
[`docs/DESIGN.md`](https://github.com/groundhold/groundhold/blob/main/docs/DESIGN.md)
— entries D1063, D1073, D1078, D1084, D1087, D1088, D1091. Groundhold verifies claims
about infrastructure, which is a poor line of work for a project whose own claims go
unchecked; that is the whole reason this walk happened and the reason it is written
down rather than quietly fixed.*
