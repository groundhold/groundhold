# Every check passed. No alarm could reach a human.

During a dogfooding run of our own tool, an operator stood up a complete monitoring
set: a health probe, two alarms, a notification topic. Everything checked out. Every
check came back green — the world already matched what had been asked for, nothing to
do.

Not one of those alarms would have reached a human being.

Both topics had **zero subscriptions**. The alarm fires, hands the notification to the
topic, and the topic has nobody to deliver it to. Four green checks, and the thing
they exist for does not happen.

## Every check passed, and every check was right

This is what makes the class worth writing about: every check did what it said, and
the gap was in what nothing had been asked to check.

- The alarms existed and were bound to real resources — every capability came back
  observed-equals-declared.
- The alarm was **armed** — the enable switch was on.
- The alarm **named a target** — the action list was not empty.
- The topic existed.

Each link verified. The chain still ends in nothing, because the last link — *is there
a subscriber behind that topic* — was not a link anything looked at.

## The trap is in the name

Our attribute was called `notify`. Its value was `true`. What it actually asserted
was:

> the action list is non-empty **and** the alarm is enabled

which is a precise, useful, checkable property, and it is not what "notify" sounds
like. "Notify = true" reads as *someone will be told*. It means *this alarm is armed
and points somewhere*.

That gap had already been narrowed once. An earlier round found the same attribute
computed from the action list **alone**, so an alarm that was switched off — pointing
at a perfectly good pager, and disabled — still reported `notify: true`. The fix ANDed
in the enable switch. It moved the boundary one link to the right; it did not move it
to the end of the chain, and nothing said where the boundary now stood.

The general shape:

> **A chain has more links than the attribute describing it. If the attribute is named
> after the outcome and computed from a link, the difference is invisible to exactly
> the person relying on it.**

Anything named `notify`, `alerting`, `monitored`, `backed_up`, `encrypted`,
`highly_available` is worth this question: what is the last link this actually reads,
and how many links are there between that one and the outcome in the name?

The operator also noted the one thing that behaved well here: the driver **refused**
the unknown operand they had reached for — a `subscriptions` field — instead of dropping
it silently. A silently ignored operand is how you come to believe you declared
something you did not.

## Zero is not evidence

The obvious fix is to count subscribers and require at least one. That is what was
added — and a real-account run corrected the shape.

The first cut treated a zero-subscriber topic as a violation. Reasonable: no
subscribers, nobody is told. But a real run showed that the provider's "subscriptions
pending" counter **lags** — immediately after subscribing, it still reads zero. So a
subscription in flight — a confirmation email sent and not yet accepted — would have
been reported as reaching nobody. A false alarm about false alarms.

There is a deeper reason it could never have been a violation, and it survives the lag
being fixed:

- **"At least N subscribers are confirmed"** is provable by reading. You saw them.
- **"This topic reaches nobody"** is not provable by reading. A zero can mean a
  subscription still pending, or a cross-account or otherwise uncatalogued one the
  witness cannot enumerate.

So the rule became: **a positive count is a measurement; zero is `unknown`.** Not
"satisfied", not "violated" — unknown, which blocks a hard requirement rather than
silently passing it or falsely failing it. A checker that cannot see something must
say it cannot see it. That is strictly more useful than a confident wrong answer in
either direction.

And the honest limit stays stated, because it does not go away: **none of this proves
a human reads what is delivered.** It proves delivery-readiness. No amount of reading
configuration will ever prove someone is on the other end of an inbox, and a system
that claimed otherwise would be lying about the one thing operators most want to
believe.

## What to check in your own stack

1. For every "someone gets told" claim, follow the chain to the end: alarm → enabled →
   action → channel → **subscriber** → a person who reads it. Mark the link where your
   checking actually stops.
2. Ask whether your config check would notice a topic, queue, webhook or channel with
   **no consumer**. Ours did not, and it is worth finding out about yours before an
   incident does.
3. When a count reads zero, ask what else zero could mean. If it can mean "in flight"
   or "I cannot see it from here", it is not evidence of absence.
4. Test the notification path itself, not the alarm: send one and watch it arrive.
   That is a different test from anything a configuration read can do.

Point four is the one that would have caught this, and it is the one least likely to
be run, because everything was already green.

---

*This came out of Groundhold's own monitoring. Both halves are recorded with the
reasoning and the code in
[`docs/DESIGN.md`](https://github.com/groundhold/groundhold/blob/main/docs/DESIGN.md):
the narrowed claim (D1027) and the witness that can prove presence but never absence
(D1030). The capability to require a subscriber did not exist when this was found —
that gap was the finding, not a bug in a driver.*
