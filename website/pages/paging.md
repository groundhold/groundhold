# One page, and when it is never enough

*A field note. It is about reading cloud APIs correctly, and you do not need
Groundhold — or any tool — for it to be useful.*

Every cloud API paginates. Everyone knows this. The bugs do not come from
forgetting it; they come from a read where paging genuinely does not matter
sitting three lines away from one where it decides the answer, and the two
looking identical.

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

## What it looked like in production

Three real ones, from a sweep of every read that lists something and then acts on
it.

**A service reported gone while it was running.** A function resolved a service by
matching a name against one page of a listing capped at twenty. Not found on page
one meant "gone, never created" — and every caller took that as fact. Create would
mint a *second* service. Delete would report success having deleted nothing.
Observe would record the resource as absent.

**A network reported closed while a door stood open.** A check asked whether *any*
security group opened a path to everywhere, and read one page. EC2 returns a
thousand groups per page and the per-VPC quota is 2500. So on a large estate the
answer was "no" — and "no" became the value `egress.restricted = true`, tagged as
measured, while `-1` to `0.0.0.0/0` sat on page two.

**A network reported to have no route out while it had one.** The same defect four
lines earlier: one page of route tables, a hundred per page, quota 200, one table
per subnet being an ordinary layout. "None" is the tightest possible answer, so the
truncation manufactured exactly the reassurance an operator would act on.

## Why this class is worse than an ordinary bug

Truncation does not produce random wrong answers. It produces **reassuring** ones.

A partial read of "is anything dangerous here?" returns *no*. A partial read of "is
there a way out of this network?" returns *none*. A partial read of "does this
already exist?" returns *no, go ahead and create it*. The failure mode of looking
too little is a clean bill of health, every time, and nobody investigates a clean
bill of health.

Which gives the sentence worth taking away:

> **"I stopped looking" and "there is nothing there" must never arrive as the same
> value.**

If a sweep cannot finish — a page limit, a throttle, a timeout — that is an
*error*, not an answer. Returning the partial result as though it were complete is
how a network gets certified as closed.

## The three cases where one page is genuinely enough

Not every unpaged read is a defect, and treating them all as one is how a real
finding gets lost in noise.

**The question is emptiness.** "Only a cluster with zero node groups gets a fresh
one" is answered by page one, correctly and forever.

**The filter is server-side.** If the API does the matching — you pass an ID and it
returns that resource or nothing — there is no second page to miss. The danger is
specifically a *client-side* filter over a listing: the server hands you a page, you
search it yourself, and your search is only as complete as the page.

**A quota makes the second page impossible.** Twenty attached policies per role.
Five targets per rule. Fifty listeners on a load balancer against four hundred
returned per page. These cannot truncate, because the service will not let the
collection grow past one page.

That last one carries a condition, and it is the one people skip: **write the quota
down**. "Probably fine" and "bounded by a published limit of twenty" are different
claims, and only the second one survives someone raising the quota two years from
now. An unstated assumption does not fail loudly when it stops being true — it just
stops being true.

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

*This came out of Groundhold, which verifies claims about infrastructure and
therefore cannot afford to make unverified ones itself. The rule and the three
defects are recorded in full, with the code, in
[`docs/DESIGN.md`](https://github.com/groundhold/groundhold/blob/main/docs/DESIGN.md)
(entries D860–D864) — including the part where the same question was asked of the
other two clouds and turned up nothing, which is also a result.*
