# When one page is enough — and when it never is

Every cloud API paginates. Everyone knows this. The bugs do not come from forgetting
it; they come from a read where paging genuinely does not matter sitting a few lines
away from one where it decides the answer, and the two looking identical.

Here is the rule that separates them.

## Two questions that look alike

**"Is this list empty?"** — one page settles it. Pages fill in order, so a
non-empty collection has a non-empty first page. If page one is empty, the
collection is empty. Reading further cannot change the answer.

**"Does any element satisfy P?"** — nothing but the last page settles it. A full
first page says exactly nothing about an element that is not on it. You have to
walk to the end, or you are not answering the question you asked.

Both are `list()` followed by an `if`. Only the second one is a bug when you stop
early.

## Three from our own code

These came out of sweeps of our own cloud reads — the ones that list something and
then act on the result. They were found by audit rather than by anyone reporting them,
and two of the three were in code that reports on security posture.

One qualifier, because leaving it out would be the same sin the essay is about: the
*consequence* was not hypothetical even before these three. The security-group file
already carried a field report of exactly this outcome — a hard constraint reported
satisfied on a network whose every security group allowed `-1` to `0.0.0.0/0` — from an
earlier era when that driver answered the question a different way. The mechanism below
is new; the way it fails had been seen.

**A service would be reported gone while it was running.** A function resolved a
service by matching a name against one page of a listing capped at twenty. Not found
on page one meant "gone, never created" — and every caller takes that as a fact.
Create would mint a *second* service. Delete would report the service gone while it
stood. Observe would record the resource as absent.

**A network would be reported closed while a door stood open.** A check asks whether
*any* security group opens a path to everywhere, and read one page. EC2 returns up to
a thousand groups per page and the per-VPC quota is 2500. On a large estate the open
group sits on page two, the answer comes back "no", and "no" becomes
`egress.restricted = true`, with derivation *measured* — a guarantee, asserted.

**A network would be reported to have no route out while it had one.** The same
defect four lines earlier: one page of route tables, a hundred per page, quota 200,
one table per subnet being an ordinary layout. "None" is the tightest possible answer,
so the truncation manufactures exactly the reassurance an operator would act on.

That second one deserves the obvious comment before someone else makes it: a tool
built on never reporting "checked" for something it did not check had tagged a one-page
read as a measurement. The sweep started from the App Runner defect and found it — which
is why the rule below is written down rather than remembered.

## Why this class is worse than an ordinary bug

Truncation does not produce random wrong answers. It produces **reassuring** ones.

A partial read of "is anything dangerous here?" returns *no*. A partial read of "is
there a way out of this network?" returns *none*. A partial read of "does this already
exist?" returns *no, go ahead and create it*. The failure mode of looking too little
is a clean bill of health, every time, and nobody investigates a clean bill of health.

The rule:

> **"I stopped looking" and "there is nothing there" must never arrive as the same
> value.**

Where a read can stop before the end — a page bound, an endless token chain, and in
the general case a throttle or a timeout — that is an *error*, not an answer. Returning
the partial result as though it were complete is how a network gets certified as closed.

## The three cases where one page is genuinely enough

Not every unpaged read is a defect, and treating them all as one is how a real finding
gets lost in noise.

**The question is emptiness.** "Only a cluster with zero node groups gets a fresh one"
is answered by page one, correctly and forever.

**The filter is server-side.** If the API does the matching — you pass an ID and it
returns that resource or nothing — there is no second page to miss. The danger is
specifically a *client-side* filter over a listing: the server hands you a page, you
search it yourself, and your search is only as complete as the page.

**A quota makes the second page impossible.** Twenty attached policies per role. Five
targets per rule. Fifty listeners on a load balancer against four hundred returned per
page. These cannot truncate, because the service will not let the collection grow past
one page.

That last one carries a condition, and it is the one people skip: **write the quota
down**. "Probably fine" and "bounded by a published limit of twenty" are different
claims, and only the second one survives a later quota change.
An unstated assumption does not fail loudly when it stops being true — it just stops
being true.

## What we deliberately did not fix

One shape came out of the sweep and was left alone, on purpose.

A delete path lists a resource's children before removing them. A truncated list
leaves children behind — but the delete then *fails* on the dependency, says so, and
the retry reads the next page. It is wrong, it is loud, and it corrects itself.

That is a different risk class from a read that quietly returns "nothing here", and
conflating them costs you the ability to prioritise. A bug that announces itself can
wait. A bug that produces a reassuring answer cannot.

## The check you can run today

Take the reads in your own codebase that list something and then act on the result,
and ask of each:

1. What question is this actually asking — *empty*, or *does any element satisfy P*?
2. Is the filter server-side, or am I searching the page myself?
3. If it is bounded by a quota, is that quota **written down** next to the code?
4. If the listing were truncated, would the wrong answer be the reassuring one?

Question four is the triage. Where the answer is yes, that read is load-bearing for
somebody's belief that their infrastructure is safe.

---

*The sweep was of Groundhold's own cloud reads. The rule and the three defects are
recorded in full, with the code, in
[`docs/DESIGN.md`](https://github.com/groundhold/groundhold/blob/main/docs/DESIGN.md)
(entries D860–D864) — including the part where the same question was put to GCP and
Azure: the dangerous shape, a definite absence feeding a create, does not occur on
either; two instances of the loud self-correcting kind do. A negative result is still a
result, and it is not the same as finding nothing.*
