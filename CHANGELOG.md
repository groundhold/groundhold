# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project is
**experimental (`v0.x`)**, not a supported or LTS release line.
See [`docs/MATURITY.md`](docs/MATURITY.md) for what is proven vs merely built.

The authoritative, rationale-carrying decision log is
[`docs/DESIGN.md`](docs/DESIGN.md) (append-only). This file is the human-facing
summary; DESIGN.md is the record.

## Read this before matching a version number

**The `## [v0.1.x]` headings below are BUILD versions, not the releases you can
download.** They are two independent sequences that happen to share the `v0.1.x`
shape, and they do not line up — the same string means a different artefact in
each. `[v0.1.8]` below is dated 2026-08-02 and is about CloudWatch alarm
operands; the release tagged `v0.1.8` was published 2026-08-14 and is a rebuild
on a patched Go toolchain. Neither is wrong; they are simply not the same thing,
and the collision was live on this page until D1078.

Published releases are cut on their own, slower cadence. Each is listed here with
the mirror commit it was built from, so anything you downloaded can be traced to a
tree you can check out — `BUILDINFO.txt` inside every release states the same
commit, the exact toolchain and the build command.

**This ends with the next release, and here is the rule that replaces it.** A `v*`
tag now means a published release and nothing else: the development line has stopped
using version-shaped names, so there is only one sequence left that looks like a
version, and it is the one you can download. Because the two sequences overlapped up
to `[v0.1.17]`, the next published release is **`v0.1.18`** — numbering continues past
the highest build number rather than walking back through nine more collisions. The
gap between `v0.1.8` and `v0.1.18` is that overlap, not missing releases.

| release | published | built from | contains |
|---|---|---|---|
| `v0.1.8` | 2026-08-14 | `00fa5c1e` | everything through `[v0.1.17]` below, plus the work recorded in `docs/DESIGN.md` up to D1073. Rebuilt on Go 1.26.6 for stdlib fixes; `v0.1.7` predates that toolchain. |
| `v0.1.7` | 2026-08-13 | `5238973b` | everything through `[v0.1.17]` below, plus DESIGN entries up to ~D1024 |
| `v0.1.6` | 2026-08-13 | `45c4e548` | everything through `[v0.1.17]` below |
| `v0.1.5` | 2026-08-11 | `b3d650a9` | everything through `[v0.1.17]` below |
| `v0.1.4` | 2026-07-26 | (predates `BUILDINFO.txt`) | superseded — tagged from a commit whose gate was red, which is why `v0.1.5` exists |

The entries below begin at `[v0.1.3]`: the build tags before it predate this file and
have no section of their own.

**The version-by-version entries below stop at `[v0.1.17]` (2026-08-06) and the
development line has continued past it.** For anything newer, `docs/DESIGN.md` is
the complete record — every change lands there with its reasoning, numbered, before
it reaches a release. This page trails it by design; it should not trail it silently,
which is what the table above and this paragraph exist to prevent.

## [Unreleased]

## [v0.1.17] - 2026-08-06

Three reads that answered from an unfinished sweep. Two of them turned a partial read into a
MEASURED security guarantee, and both were in v0.1.16.

### Measured claims from page one

- **A VPC's egress reported restricted while a group opened it** (D863).
  `describeVpcSecurityGroupPosture` asks whether ANY security group opens a door to
  everywhere and read one page. EC2 returns a thousand groups per page; the per-VPC quota is
  2500. `observe` turns the NO into `egress.restricted = true`, derivation `measured` — so on
  a large estate the tool measured a network as restricted while `-1` to `0.0.0.0/0` stood on
  page two.

- **A VPC reported to have no road out while it had one** (D864). The same defect four lines
  earlier: `describeVpcRoutes` read one page of route tables (a hundred per page, quota 200,
  one table per subnet being an ordinary layout) and its answer becomes `egress.internet` —
  with "none" also producing `egress.restricted = true`. `none` reads as the tightest possible
  answer, so the truncation manufactured exactly the reassurance an operator would act on.

- **An App Runner service reported gone while it stood** (D860). `resolveServiceArn` matched a
  name against one page of a listing capped at TWENTY services and returned "gone/never-created"
  for a name it had not seen. Every caller takes that as fact: create mints a SECOND service,
  delete reports gone, observe reports absent, claim cannot take over.

All three now read every page, bounded, and a sweep that cannot finish returns an ERROR
rather than an answer: "I stopped looking" and "there is nothing there" must not arrive as
the same value.

### The rule that found them

- **One page settles "is this list empty"; nothing but the last page settles "does any
  element satisfy P"** (D861, corrected by D863). Pages fill in order, so a non-empty list has
  a non-empty first page — which is why `ensureEKSNodeGroup` is correct reading one. A
  client-side filter over a listing needs every page; a server-side one needs none, which is
  what makes `describeEC2Instances` (always called with `InstanceId.1`) safe.
- The same question asked of GCP and Azure found no instance of the shape (D862).

### Instruments

- **k8s mapped surfaces are checked against the schemas Kubernetes publishes** (D858). D509's
  guard needed a live cluster and skipped in every run here and in CI; the same OpenAPI v3
  documents a cluster serves are published, so the seven built-in mappings are now verified
  offline on every `make check`. The three CRD mappings still need a cluster, and are counted
  rather than passed over.
- **Every gate file now carries a mutant, and each was tried by hand first** (D856, D859).
  Thirteen had none; twelve bit when injected with the defect they claim to catch, and one —
  the k8s discoverability certificate — passed over an empty subject and was fixed.

### Not changed

No new permissions, no format change, no vocabulary change. A plan for the same candidate
should be identical to v0.1.16's.

## [v0.1.16] - 2026-08-06

Cut for one defect that shipped inside v0.1.15: a budget alert that could never be created.

### The blocker

- **A call AWS does not have** (D853). The budgets driver had always sent
  `X-Amz-Target: AWSBudgetServiceGateway.CreateNotificationWithSubscribers`. There is no such
  operation — `NotificationsWithSubscribers` is a FIELD of CreateBudget, and the call is
  `CreateNotification`. The request BODY was correct all along: its four members are exactly
  CreateNotification's four required inputs. So on AWS `capability.cost.budget` — whose point
  is the threshold alert — could never finish a create: the budget landed, the notification
  was rejected on the target name, and the result was `unknown`. Both authorities agree
  (AWS's Service Reference and botocore), and four tests broke on the fix because their fakes
  served the old name: a fixture is written to match what the driver sends, so driver and
  suite were consistent with each other and both wrong about AWS.

### Permissions

- **Six more action paths declared what they call** (D853). Aurora's create builds a DB subnet
  group and a cluster parameter group and its delete removes both; ElastiCache does the same
  with its cache subnet group; the ECS delete reads the CLUSTER's tags to prove ownership; the
  KMS create lists keys to find one it already owns. Eleven permissions in total — grant them
  before upgrading, or the preflight will refuse before anything moves.

### Instruments

- **Twenty-seven services became visible** (D853). For the Query and JSON protocols the
  operation is named in the request body or an `X-Amz-Target` header, never in the path, so
  the route recorder had been collapsing every call a service makes into one line. Recording
  the operation took the recorded set from 195 lines to 452 and turned 240 unverifiable
  routes into verifiable ones — `uncheckableRouteCeiling` fell from 28 to 1 rather than
  rising to 240.
- **A discoverability certificate over zero services is refused** (D856). Thirteen gates had
  no mutant; each was injected by hand with the defect it claims to catch. Four bit. The
  k8s one passed with an empty subject — a driver that can discover nothing certified as
  fully discoverable.
- **A fix held only by a gate that reads a checked-in file** (D857). The meter found that
  re-injecting the budgets defect broke nothing under a filtered run, because the route gate
  compares recorded data rather than code. The fix now has a test that drives the driver.

### Measured and recorded, not built

- 180 mutating requests carry every field AWS requires; the five apparent gaps were
  wire-naming rules (D854).
- cloudflare, hetzner and k8s agree with their providers' published specs; upstash publishes
  none (D855).

## [v0.1.15] - 2026-08-05

Seventy-six decisions since v0.1.14. Two threads run through them: **claims confronted with
the providers' own published models**, and the first change the code freeze was lifted for.

### From the field

- **A contract can name who may invoke a function** (D852). `implementation.invokers` writes
  scoped resource-policy statements — an IAM principal, or a service principal narrowed by
  `source_arn`. Reported because the alternative was a hand-written `lambda:InvokeFunction`
  grant to `Principal: "*"` with no condition, on the function it was meant to protect. A
  service principal WITHOUT a `source_arn` is refused: it authorises that service in every
  AWS account, which is the wildcard the operand exists to remove. Grants are RECONCILED
  against the live policy, so an entry dropped from the candidate is withdrawn rather than
  merely un-added, and only statements under our own prefix are ever touched.

- **Operands are recorded in the ledger verbatim, and now the schema says so** (D851). A
  scheduled invocation carries no headers, so a payload operand is the only channel a job
  has — and nothing warned that what goes in it is persisted for the life of the ledger. The
  shape-based credential detector cannot recognise an arbitrary random secret, so the
  sentence that matters most is that ITS SILENCE IS NOT A CLEARANCE.

### Permissions, confronted with AWS's own register

- **Two permissions an operator cannot grant** (D846). `apigateway:TagResource` is not an
  action — API Gateway authorises by HTTP verb — and AWS publishes no
  `cloudfront:CreateDistributionWithTags`. Both sat in the list operators build IAM policies
  from. Every declared permission is now checked against AWS's Service Reference.

- **Permissions sufficient for the plan, missing for what the plan does** (D848, D850, D849).
  Six declarations were short, all on paths where the denial lands MID-PLAN: the EKS
  node-group roll after an irreversible control-plane upgrade, Lambda's code push and
  exposure teardown, S3's going-private policy delete and its pre-delete object-lock read,
  SES's default configuration-set, and Bedrock's create-adoption listing. Under-declared is
  worse than misspelled: a misspelling refuses before the lease.

### Honesty

- **A grant nobody could read, recorded as a measured "not public"** (D847). When a Lambda's
  resource policy could not be read, the driver answered `network.publicExposure = false`
  with derivation `measured` and put the truth in a diagnostic. Only the record travels, and
  `measured` is full-strength evidence — so a hard `publicExposure == false` came back
  SATISFIED for a function that may be world-invokable.

- **Eleven replacements no provider asks for** (D806, D821-D825). Verdicts that destroyed and
  recreated resources — including disks and buckets, where a replacement means losing what is
  in them — to reach states the provider patches in place.

- **A schema claiming a coverage it did not have** (D845). `spec/outputs.schema.json` said
  "one $def per verb" with defs for less than half of them.

### Instruments

- Routes, permissions, API versions and field names are now confronted with botocore, AWS's
  Service Reference, Google's discovery directory and Microsoft's ARM schemas — offline, on
  every `make check`, with no credentials (D820, D839-D843, D846, D850).
- The mutation meter checks its own anchors in forty seconds before a three-hour run (D819).

## [v0.1.14] - 2026-08-04

Cut for one blocker and shipped with what was ready beside it. The field asked for it and
answered the timing question themselves: *tak, uzasadnia — ale nie prosimy o pośpiech
kosztem Waszych bramek.*

### Blocker

- **A create operand blocked capabilities nobody was creating** (D774). Four ZIP-packaged
  functions — bound, converged, untouched by the plan — blocked the plan of 43
  capabilities, 39 of which have nothing to do with Lambda. The operand-drift step derived
  its desired shape through the create builder, which refuses without `image_uri`. The
  question asked was "has this drifted"; the answer came back "you have not told me how to
  build it". **A create requirement is not a drift requirement.**

- Two more in the same report, one principle: **a missing piece should refuse where it is
  used, not everywhere.** `observe` recorded outputs all-or-nothing, so one unreadable
  output discarded every readable one — including the ARN the driver had just adopted the
  resource BY. And `functionUrl` was treated as mandatory on functions declaring
  `network.publicExposure: false`, where its existence would have violated the reporter's
  own security constraint; `Conditional` is a field now, not a sentence in a comment.

### Honesty

- **A probe that dialled nothing said it had** (D775). All three probers stamped
  `tcp-connect` on a value read from a config flag. Two also folded an UNKNOWN address
  into a proven `network.publicExposure: false` — the safest-sounding possible answer
  about a public database, invented out of missing data.

- **Two trust operands were not two spellings of the same thing** (D776). `trust_service`
  writes a bare service principal and NO condition; the refusal called it "the common
  case". All six of the reporter's roles carry a condition, so following that advice would
  have recorded trust WEAKER than the trust that stands — undetectably, because
  `trust.principals` is not an attribute.

- **The hardening advisor shipped the weakest bar with its own advice** (D773). Every
  snippet carried `verify: {method: static}` — the bar the author's own declaration meets
  — for encryption, exposure, flow logs and rotation. The bar is derived from what can be
  read now.

- **An unprovable hard constraint is named** (D769), and a switch that adds a
  separately-billed component is named beside a declared cost (D770). Neither refuses:
  the project's own thesis example declares an unprovable requirement on purpose.

### Gates

- Every operand a driver READS must be declared consumed (D763) and every flag a message
  NAMES must be one the binary parses (D764) — both found a dead end where the tool's own
  advice pointed at something that did not exist.
- Every service a driver CERTIFIES must answer when asked (D771): 145 checked, zero gaps.
- The two gates added that morning were themselves mutated (D767), and the three
  foreign-DELETE registers — the ones whose failure cannot be undone — got their first
  mutants ever (D768).

### Compatibility

- No format change since v0.1.13. The `platform-invariant` derivation landed there; a
  ledger written by v0.1.13 or later is still not readable by anything older.
- No new breaking refusal. D776 changes the WORDING of two existing refusals, not their
  conditions.


## [v0.1.13] - 2026-08-04

Nineteen decisions. The shape of the day was a method rather than a theme: **ask a
question of a LIST, not of a file.** Six questions were asked; four found something.

### Security

- **A firewall guarding nothing looked exactly like one that works** (D765). Measured on
  a live production estate: a WebACL with sensible rules — including a rate limit the
  reporter relies on as a defence against enumeration and stalking, not as a performance
  control — in the wrong scope, with `ResourceArns: []`. `managed.ruleset` means "am I
  PROTECTED by the managed baseline"; the driver now looks at whether any distribution
  names the ACL, and an unread listing leaves the attribute unobserved rather than
  claiming protection. `bot.protection` is about the RULES and correctly stays.

- **A role trusting the account root is WIDER than a service role, not narrower** (D751).
  A candidate declaring neither `trust_service` nor `assume_role_policy` silently got
  account-root trust: no service could assume it, and every principal in the account
  could. The field built five such roles and could not attach one to a Lambda. **This is
  a BREAKING change** — a contract with no trust operand is now refused, which is what
  the reporter asked for.

- **A default is not a guarantee** (D761). Azure PostgreSQL `encryption.inTransit` was
  asserted true for every server, justified by the DEFAULT of `require_secure_transport`
  — a parameter an operator can turn off, after which the server accepts plaintext.

- **An unlocked GCP backup vault was reported as WORM** (D752), and the driver never sent
  a lock time, so every vault it built was one. **A Cosmos account in a single zone was
  reported as replicated across zones** (D753) while the create sent `isZoneRedundant:
  false`. **A Fargate service whose subnets sit in one zone was reported regional**
  (D754). Three assertions of a platform guarantee that was not one, in a single day.

- **A secret inside its deletion window was reported healthy** (D756). AWS keeps
  answering `DescribeSecret` through the recovery window, so every observation stayed
  true while `GetSecretValue` already refused.

### Correctness

- **`publicExposure` was measured under one definition and validated under another**
  (D749). The edge pattern sits between them, so the only declaration the tool accepted
  made every plan want to ADD an anonymous invoke grant to an IAM-protected function.

- **A deny from a simulation we deliberately under-specified was treated as authoritative**
  (D750). "Omitting the region key is safe" holds only for a policy that NEEDS the key; a
  guardrail written as `Deny` + `StringNotEquals` needs none, denies, and reports nothing
  missing. The field was told it lacked permissions it demonstrably had.

- **Two refusals pointed at each other** (D763). GKE refused unless you supplied
  `masterAuthorizedCidrs`, and supplying it was refused as "not an operand the driver
  reads" — which the driver did read. A private-endpoint cluster could not be expressed.

- **posture called an advisory failure "drift" and an advisory pass "ok"** (D755).

- **The one remediation for a live run named a flag that does not exist** (D764).

### Honesty

- **A third derivation** (D759/D760): `platform-invariant`, for a fact true of every
  instance of a service. 65 of 72 `config-intent` observations were that, wearing a label
  whose published definition says the resource STORES the value. It sits at the same
  evidence bar — honest provenance, never more trust — and 48 sites were relabelled one
  at a time, 17 deliberately left, one found to be a defect (D761).

- **"observed" was printed over a number the author had written** (D766). A budget
  constraint compared a declaration to a threshold and reported `observed 6 EUR` while
  the bill was 14.6. The verb now follows the provenance.

### Gates

- The effect-attribute class gate reads the AST, because comments, diagnostics and a
  declaration all satisfied earlier versions of it (D748).
- Every field the drivers DECODE must be served by some fixture (D756) — five entries in
  a row were slowed by a fake that could not contradict the code.
- Every operand a driver READS must be declared consumed (D763), and every flag a message
  NAMES must be one the binary parses (D764).

### Compatibility

- `platform-invariant` enters the ledger event schema. A ledger written by this binary is
  **not readable by an earlier one**. Take a copy before the first `observe`/`apply` if
  you may want to go back.
- Contracts declaring an AWS `iam` capability with no trust operand are now REFUSED
  (D751). Add `implementation.trust_service`, or `assume_role_policy` for a full document.
- `url_auth: iam` with `network.publicExposure: true` is now refused as a contradiction
  (D749); the edge pattern declares `false`.


## [v0.1.12] - 2026-08-04

Twelve decisions from one night of field reports and one sweep of what they generalize
to. Eleven of the twelve are the same sentence in different clothes: **the tool read a
container and reported its contents, a switch and reported its effect, or a name and
reported the thing named.**

### Security

- **The AWS Backup vault lock was built backwards** (D724). `ChangeableForDays` is what
  makes a lock immutable; the driver set it for `governance` and omitted it for
  `compliance`. A contract asking for the reversible mode got a lock **nobody can ever
  remove**, including the account root, and one asking for WORM got a lock deletable at
  any time. Observe read `Locked` as compliance, and `Locked` is true in both modes.

- **A replacement could adopt the resource it was about to delete** (D723), destroying it
  while both actions reported success.

- **GuardDuty could never be created on a real account** (D735). Its REST-JSON body is
  camelCase and the driver sent PascalCase, so the required `enable` field never arrived.
  Every READ worked the whole time, because Go's decoder matches case-insensitively and
  its encoder does not.

- **Controls that were on and doing nothing**, each with the deciding field already in a
  response the driver had: CloudTrail delivery and VPC flow logs (D725), alarm arming on
  all three clouds (D726), a backup plan protecting nothing (D733), a GCP audit sink
  whose destination grant nobody verified (D738), an Azure WAF switched off (D739), a GCP
  subnet sampling zero flows (D742), an Azure NSG standing for its own rules (D744), a
  dead-letter queue that had been deleted (D745), and a bounce sink nothing routed to
  (D746).

- **AWS `egress.restricted` is measured from the security-group rules** instead of from
  whether a road to the internet exists (D743). A road says which way traffic leaves and
  never where to.

### Correctness

- **The permission preflight asked a different question than apply would** (D720): no
  request context, so an account whose guardrail is written in `aws:RequestedRegion`
  had every touched action reported as denied.

- **A `config-intent` reading satisfied a hard constraint** (D722). The evidence ladder
  keyed on an observation's source and ignored what it had witnessed.

- **A constraint can now carry two evidence bars** (D728): `verify: {design: static,
  runtime: provider-api}`, because `verify` compares a contract with a candidate before
  anything exists and `audit` judges recorded reality.

### Honesty

- **`plan` now says which capabilities it could not cover** (D721), and refuses when one
  is named in no other channel.

- **Refusals route at doors that exist** (D730/D731): `unadopt` pointed at a `retire`
  verb this binary does not have, and the credential refusal never mentioned the
  `AWS_PROFILE` sitting in the environment.

- **`--provider cloudflare` was accepted and answered with fabricated reality** (D734).
  Four copies of the provider-to-driver mapping existed and three fell through to the
  fake. There is one now.

- **The loader names every unknown capability type at once**, each with the closest known
  ones (D719), instead of refusing at the first over a closed vocabulary it was holding.

## [v0.1.11] - 2026-08-03

Four decisions, all in one class: **a control that exists and does nothing**. Two came
from a tester's field reports, two from sweeping what those reports generalize to, and
all four were checked against the vendor's published contract rather than recalled.

### Security

- **A replacement could adopt the resource it was about to delete** (D723). The
  pre-create scan keyed on ownership tags, which carry no generation, so a generation-2
  create could bind the generation-1 resource and return its id with zero mutations —
  and the delete that follows, pinned to that same identity, destroyed it. Both actions
  reported success. Refused in the executor before the binding is written, whatever any
  driver's scan does.

- **The vault lock was built backwards** (D724). `ChangeableForDays` is what makes an
  AWS Backup vault lock immutable; the driver set it for `governance` and omitted it for
  `compliance`. A contract asking for the reversible mode got a lock nobody can ever
  remove, and one asking for WORM got a lock deletable at any time. Observe read
  `Locked` as compliance, and `Locked` is true in both modes.

- **Two controls were on and delivering nothing** (D725). `delivery.assured` came from
  `IsLogging`, which AWS defines as "StartLogging was called" — a trail whose bucket
  refuses the writes keeps it true forever. `flowLogs.enabled` was "a flow log row
  exists"; a tester's flow log with an unassumable role reported ACTIVE and wrote zero
  records.

- **An alarm that names a pager and will never ring it** (D726). All three clouds keep
  the arming switch separate from the action list, all three creates set it, and no
  observe read it back.

- **The flow-log role is read before it is handed work** (D727), so a control that
  cannot deliver is refused rather than built. On the way: the batch outcome was decided
  by two substring tests against a response shape AWS does not send, so **every
  successful flow-log create was reported as a failure** — on a composite that had
  already built the network.

## [v0.1.10] - 2026-08-03

Six decisions, all from two testers running the binary on live accounts, plus one
sweep of what those reports generalize to. The shape they share: **the tool held the
answer and either did not ask for it, did not say it, or threw it away.**

### Security

- **A permission preflight simulated with no request context** (D720). An account whose
  guardrail is written in `aws:RequestedRegion` — an EU-only residency rule — had every
  touched action reported as denied, ~65 of them, none actually missing. The pilot's
  workaround was to detach that guardrail for the length of each apply: our tool made
  them switch a security control off so our tool would agree the control was satisfied.
  The simulation now carries the region where the call actually runs in one, and AWS's
  own `MissingContextValues` makes any verdict resting on a key we withheld
  *unattested* rather than denied — which covers the guardrails nobody can enumerate.
  An audit of the fix caught it re-creating the same bug for `iam:*` and `route53:*`,
  which have no regional endpoint.

- **A `config-intent` reading satisfied a hard constraint** (D722). The evidence ladder
  keyed on the observation's SOURCE and ignored its DERIVATION, so "the resource stores
  this value" and "we measured this value" ranked the same. A network read
  `egress.restricted: true, satisfied` while both its security groups allowed everything
  outbound. A config-intent reading now sits at the `static` bar and no higher: ask for
  `provider-api` or `probe` evidence and you get `unknown`, which on a hard constraint
  blocks.

- **A replacement could adopt the resource it was about to delete** (D723). Create at
  generation N+1 scanned for a resource carrying our ownership tags — which do not carry
  the generation — bound the generation-N resource, and the delete that followed,
  pinned to that same identity, destroyed it. Both actions reported success. Refused now
  in the executor, before the binding is written, whatever any driver's scan does.

### Correctness

- **An MSK cluster delete addressed a route AWS does not have** (D717). MSK carries two
  API versions and `DeleteCluster` exists only on v1; an unmatched route answers 403,
  which reads as a denied permission — so every retire failed while telling the operator
  to widen IAM. Found by asking real AWS about every route the drivers build (191 across
  40 services); the gate that should have caught it covered 29 routes across 2.

- **Two GCP services read their IAM policy under POST**, where Google routes only GET
  (D718), so `network.publicExposure` was unreadable on both and the public-grant paths
  could never succeed.

### Honesty

- **`plan` never said which capabilities it could not cover** (D721). The reason was in
  `plan.blocked` all along; the verb printed the JSON, named the converged no-ops on
  stderr, and exited 0. A pilot applied 24 actions for a 27-capability contract and
  learned what was missing from converge afterwards.

- **The loader refused at the first unknown capability type and suggested nothing**
  (D719), over a closed 57-type vocabulary it was holding at that moment. It now names
  every unknown type in one run, each with the known types nearest to it.

## [v0.1.9] - 2026-08-02

Sixteen decisions, and they cluster into three shapes. Every one was found by asking
the same question of a different surface: **what does this say when it does not know?**

### Security

- **A trust policy the runtime could not read armed nothing, silently.** An anchor
  beside the ledger carries the policy every verb verifies under, and the load test
  read a CORRUPT anchor exactly like an absent one — so no trusted keys were added, no
  `trustFrom` cutoff was set, and events the policy required to be signed were accepted
  unsigned, on every verb. Absent and unreadable are now different answers, and the
  unreadable one refuses.
- **Retiring a security posture no longer switches it off.** `capability.security.threatdetection`
  is stateless, so nothing asked before a plain `--yes` retirement disabled threat
  detection for a region. A `protection: true` marker says a delete removes a CONTROL
  rather than a resource; retiring one refuses unless the contract scopes
  `autonomy.allow_protection_lift` to it. Dropping the capability from the contract
  instead leaves the control ON, and `posture` reports it as unmanaged — which is true.
- **A publicly reachable Lambda was observed as private** (also in v0.1.7): the
  resource-policy read used an API version that has no policy route, and AWS's 404 for
  our own bad URL was taken as an answer about the account.

### Fixed

- **The probe verbs stopped calling "I could not tell" a success.** The reachability
  probe had two verdicts, so a 5xx and a transport failure arrived in the same bucket;
  there are three now (`reachable`, `unknown`, `failing`), and a confirmed failure is
  recorded as a measurement rather than dropped. The `probe` verb reported `probed`
  with exit 0 when every measurement had failed; it answers `probed` / `partial` /
  `unmeasured` and exits 2 for the last two. Every result also says WHAT was checked —
  reachability and status class only, the body is not read — so a 2xx carrying an error
  payload cannot read as health.
- **An unreadable snapshot stopped meaning "no snapshot".** One loader answers three
  ways and three callers tested two: `runs`, `status` and `wait` silently skipped the
  archive, so a run recorded before a compaction answered "no such run". Backup and
  attest had the same fold, caught by a neighbour that fails closed.
- **`repair --quarantine` no longer empties the ledger path.** It renamed the history
  aside and then renamed the prefix in; a crash between the two left no ledger, and a
  missing ledger replays as an EMPTY one — so the next converge would have planned a
  create for every capability already standing.
- **An integrity pin is written or the operation refuses.** The anchor's snapshot pin
  was best-effort, and the swap check only compares a non-empty pin, so a hash failure
  left swapped-fold detection silently off.
- **The agent-facing MCP surface stopped answering over the top of the verbs.**
  `verify` exiting 2 is a VERDICT, not a refusal, and it was reported as one; an
  unknown exit code produced an empty status; `groundhold_apply` published a driver
  list three drivers out of date next to a correct copy; twelve sites answered with a
  status word in no published set, half of them in a different payload shape; and the
  five refusals the server raises itself carried prose with no machine code.

### Added

- **`aws/cloudwatch` reads the five operands that decide whether an alarm fires**
  (v0.1.8): `dimensions`, `statistic`, `period_seconds`, `evaluation_periods`,
  `treat_missing_data`, with observe reading them back so a change is drift.
- **A vocabulary key nothing reads is refused, not dropped.** Twelve attributes carried
  a `note:` holding the sharpest prose in the vocabulary — what static verification
  proves versus what an outcome probe proves — and no reader ever saw a word of it.
  `explain` prints it now, both loaders enforce a closed key set, and the nine
  attributes that had no description have one.
- **`survey` says when a capability was witnessed only by its type.** A finding names a
  TYPE, so one repo witnessing one database silenced every database of that type —
  information, never drift, and previously not reported at all.
- **Published mapping tokens name services that exist.** 42 keys named a driver service
  token no driver has; 31 were renamed by asking the drivers, and the 11 that remain
  sit on two capability types nothing builds.

## [v0.1.8] - 2026-08-02

Carries the v0.1.7 fix; adds the operands a monitoring contract needs to state an
alarm that can actually fire.

### Added

- **`aws/cloudwatch` reads the five values that decide whether an alarm fires.**
  `dimensions`, `statistic`, `period_seconds`, `evaluation_periods` and
  `treat_missing_data`, from the candidate's `implementation:` block. Until now the
  driver read one operand and hard-coded the rest as "tuning": with `Average` over 300
  seconds and one period, "three failures in a quarter of an hour" could not be stated
  at all, and an alarm with no dimensions watches the dimensionless variant of a
  metric — which a dimensioned exporter never emits, so the alarm exists, the contract
  reads as covered, and it can never fire. Each value is checked against CloudWatch's
  closed set at compile time, and observe reads the live state back, so adding
  dimensions to an alarm that already exists is drift rather than a silent no-op.

### Fixed

- **A fractional whole-number operand was truncated instead of refused.**
  `period_seconds: 60.5` became 60 and passed a "must be a multiple of 60" check that
  the author's own value fails. Unreadable now, for every caller of that helper.

## [v0.1.7] - 2026-08-02

One fix, reported from a live account within hours of v0.1.6, in the dangerous
direction. **Supersedes v0.1.6 for anyone using Lambda Function URLs.**

### Security

- **A publicly reachable function was observed as private.** `network.publicExposure`
  is measured from two gates — AuthType NONE and a resource policy granting
  `lambda:InvokeFunctionUrl` to `*` — and the policy read was built on
  `/2021-10-31`, the Function URL API version, which has no policy route. AWS answered
  that bad URL with a 404 and the reader took it for an answer about the account: "no
  resource policy", therefore private. Every Function URL with AuthType NONE reported
  `publicExposure: false`, with no diagnostic, while a contract declaring it exposed
  read as satisfied. The route now has one spelling shared with the two write sites;
  the test fixture matches by exact path instead of suffix (it answered whatever
  version the driver asked for, which is why no test saw this); and the live
  endpoint-reality gate, which asks the real API whether a driver's paths exist,
  covers the Lambda control plane and not only EKS.

## [v0.1.6] - 2026-08-02

Everything since v0.1.5, and most of it comes from one method: read-only audit agents
sweeping a surface at a time — posture, capsules, compaction, canonicalization,
locking, time, the reference implementation, and everything the project publishes —
while the findings are fixed one slice at a time, each with a gate and a mutant that
re-injects the bug to prove the gate has teeth.

Around 200 decisions are recorded for this span in `docs/DESIGN.md`. The recurring
shape is one thing: **silence read as agreement**. A missing observation, an
unreadable pointer, an unswept scope, an absent archive, a gate whose subject was
empty — each answered a question it had not asked. The sections below lead with that
class; the entries after them are the earlier work of the same cycle.

### Security

- **The ledger lock protected an inode while the code reasoned about a path.** A
  writer that took the lock, then had the file replaced underneath it, held a valid
  flock on a file nobody else was reading. The lock now verifies that the descriptor
  it holds is still the ledger at that path, and retries when it is not.
- **`apply` re-judges the evidence its changes rest on**, rather than trusting the
  verdict a plan carried from an earlier clock — and refuses a vocabulary it was not
  compiled against. One mutation now takes one lease; `resume` refuses a driver that
  did not start the operation it is resuming.
- **A plan that opens something up needs its own consent.** Widening exposure was
  covered by the general change consent; it is now its own gate, and a cascading
  namespace delete is marked stateful because it destroys what it cascades over.
- **Four credential detectors, four different ideas of what a secret looks like.**
  One alphabet now, shared: key tokens, compound marks and value patterns in a single
  place rather than in four that had already drifted.
- **Disaster recovery checked the wrong authority.** `restore` compared documents
  against the manifest that shipped with them instead of the ledger; a partial restore
  that recovered nothing reported success; an absent ledger read as a healthy one; an
  anchor that pinned nothing passed its own check. All four refuse now.

### Fixed

- **One freshness boundary for every verb.** Each verb had grown its own notion of
  when an observation goes stale, so the same reading was fresh to one and expired to
  another. There is one predicate now. A re-observation in the same second supersedes
  the older reading rather than losing to it, and `discover` joined the closed set of
  verbs N1 requires a clock from.
- **Six ways a document could load and mean something other than it said.** An unknown
  top-level key, a wrong-typed string field, an integer past `int64`, an unreadable
  `meta.version`, duplicate keys and YAML merge keys in the reference implementation,
  and a candidate quietly renaming the capability it implements — refused, in both
  implementations, pinned by cases.
- **A detached run was called dead without being asked.** The registry dropped pointers
  it could not read, one run's lease release could end another's, and `runs`, `status`
  and `wait` could not see a run whose events had been compacted — while a corrupt
  ledger read as an empty one. Each of those is now a question the code actually puts.
- **Compaction could eat a symlink**, and said nothing when another writer held the
  lock. It leaves an anchor behind every time now, and `export` reads the archives back
  when its window reaches below a compaction rather than reporting the gap as silence.
- **A sweep that could not reach the cloud reported an empty estate.** Unreachable
  providers now fail the sweep in every driver; a scope that listed nothing is recorded
  as such; a resource the provider says is gone is visible to `posture`; and `refresh`
  no longer counts a failed read as a refreshed one.
- **The CLI misread its own input.** Numeric flags were parsed loosely, an unwritable
  `--out` failed silently, one refusal could exit with two different codes, global
  flags were not forwarded to child verbs, and `converge` did not pass trust and
  signing settings to the verbs it runs. Each converge run also gets its own handle.
- **Everything the project publishes, run rather than read.** The CI example and
  `make plan` work again; the quickstart no longer sends GCP users to credentials the
  driver does not read; `release.yml` stopped claiming four gates it does not run; the
  live-cloud canary's teardown ships as documents instead of a `sed` that produced one
  the loader refuses; and the remediations the binary prints inside a refusal now name
  operands a reader can paste, instead of a bare verb that exits non-zero.

### Added

- **The discovery ladder answers before the contract is written.** `explain` covers
  every noun the runtime emits, says `UNBUILT` for a capability type no driver can
  realise, and says when no driver can author an attribute; `parity` lists every type.
- **The meters got floors.** The mutation gate refuses to report success on mutants it
  never ran and now carries 202 of them; absence gates require a positive control; the
  conformance suite has a case floor; and the differential harness varies its seed in
  CI instead of testing the same document forever.

### Security

- **The outbound notification payload could gain a free-text field unnoticed.** The
  terminal-run doorbell POSTs to an operator-supplied URL — the one path where a run's
  data crosses the network to an address groundhold does not control — and it carries
  only identifiers, enums and hashes, so there is structurally nothing to leak. That
  was true by construction and held by no assertion: an `omitempty` field slipped past
  the byte-pinned test, and driver text is exactly where credentials surface. The field
  set is pinned by name now, and every field must be a scalar.
- **A dangling capability name in a consent list loaded clean.** The contract loader
  refuses a grant naming a capability that does not exist — for `allow_replace_stateful`.
  `allow_intrusive_probes` was unchecked, and that is the list that SPENDS: an intrusive
  probe restores a backup into a scratch instance. A typo granted nothing and surfaced
  only when a probe refused, possibly during the incident it was meant to measure. Every
  consent list is checked now, from one list of keys rather than one branch per key.
- **The set of tools an autonomous agent can reach is pinned.** The MCP server exposes
  six read-mostly tools, with `apply` behind an environment gate and a hash-pinned
  two-step. One test guarded that boundary by name, so a seventh mutating tool would have
  arrived unremarked.

- **`make check` could report success without re-reading what it checks.** Four test
  packages read files that live OUTSIDE the Go module — the vocabulary spec, the
  output schema, the maturity document, the changelog — so Go's test cache never saw
  their inputs change and replayed a pass. The embedded vocabulary compiled into the
  binary drifted from its source for a week behind a green gate. The gate now runs
  uncached; twenty-six seconds instead of one and a half, next to a conformance run
  that already costs more.
- **A client name in an unexpected casing could reach a public export.** The
  sanitizer that genericizes it rewrites three exact spellings and finds them
  case-insensitively, so a fourth spelling survives the rewrite and only the deny
  audit stops it — and that audit runs in `make export-check`, which is too slow to
  be part of `make check`. Both defences held; nothing was published. The cheap half
  of the audit now runs in the ordinary gate, reading its token list from the export
  script rather than restating it.
- **`attest` cannot cover a ledger's last event, and now says so.** A hash chain
  protects an event through the link its successor holds; the final one has none, so
  rewriting it leaves every remaining link consistent and the integrity check clean.
  An anchor stored off-host catches it — which is what anchors are for and what the
  threat model already said. The report now states the limit where the reader is,
  next to the unsigned and archived counts it already reports.

- **The vocabulary credited one service's measurements to its sibling, and named one
  service that measures nothing.** The published `mappings:` block is what settles
  disputes about what groundhold checks — it decided a live production disagreement
  against our own driver. Its gate compared provider prefixes per capability, so
  naming `aws` once covered every AWS service beneath it. Measured by running the
  drivers: ECS emits five attribute paths and was credited with one, the other four
  pointing a reader at App Runner, whose behaviour genuinely differs; Container Apps
  was credited with one of the four it measures, and an attribute documented for two
  clouds and silent for the third reads as unsupported there. In the other direction,
  `workload.container` named `gcp.gke` on seven attributes nothing implements — an
  unbacked line is indistinguishable from a backed one and is trusted for exactly that
  reason. Gates now run each driver against its own fixtures.

- **A resource deleted outside groundhold no longer reads as convergence.** The
  provider contract had reserved `resource.absent` for a bound resource the API
  authoritatively 404s, and the compiler had always turned a fresh `true` into a
  re-create — but exactly ONE service emitted it. Everywhere else the read returned a
  diagnostic and no observation, so `converge` reported CONVERGED against a world
  that no longer contained the resource. Found by deleting five governance objects
  by hand on a live Kubernetes cluster and forcing a fresh observation. **All 102
  certification probes now assert the property**, on a ratchet that may only fall.
  Most of that work was not in the drivers: the test estate had to learn each
  protocol's way of saying "gone", each service's own not-found code, each error
  body's shape, and whether a read is a collection at all — a correct driver failing
  looks exactly like a defect.
- **S3 described a DELETED bucket as a healthy one.** `observe` emitted region,
  managed, encryption and durability — four attributes, two of them marked
  `measured` — without ever asking whether the bucket exists.
- **The execution role of a Lambda is now reconciled.** `role_arn` was read at create
  and observed nowhere, so narrowing a function's permissions in the candidate
  produced no plan and no action while reality kept the wide role. Reported from the
  field; ranked first by consequence, not frequency.
- **`network.publicExposure` reads the Function URL's AuthType.** A URL with
  `AuthType: AWS_IAM` behind CloudFront/OAC — the correct hardening — was reported as
  publicly exposed, and declaring the truth would have planned the DELETION of the
  CDN's origin. The vocabulary mapping had always said "AuthType NONE plus an
  anonymous invoke grant, BOTH"; the driver had not implemented its own mapping.
- **`backup` warns when capsules carry credential-shaped values.** An append-only
  ledger keeps everything ever recorded, so a backup faithfully copies credentials
  that were plaintext before a migration to secret references. Reported from the
  field with the right constraint attached: no redaction, because it would break the
  hash chain `restore` verifies against. Counts and locates; never prints a value,
  never refuses.

### Fixed

- **`react` could not tell a routine watch frame from an event it dropped.** Both exited
  0, so a stream consumer routing on the exit code could not see the real-time path
  losing changes — which is the failure that verb exists to prevent. A benign frame is
  now 0, an event nothing can parse is a structural error, and a real event keeps the
  posture verdict.
- **A spliced crawl re-dated every scope it did not read.** `react` re-lists one scope
  and carries the rest over from a base crawl; the result was stamped only at the top, so
  a document could state that a scope was COMPLETE as of a time it was never listed at.
  Since `status: complete` is what the shadow lower bound rests on, the age of that
  completeness is load-bearing. Each scope now records when it was listed — and
  deliberately not in the content hash, which must move only when the world does.
- **`--version` and `-v` stopped working**, and were restored in the same release. The
  new unknown-flag refusal closed on them: they were read from the positional list rather
  than the flag switch. The POSIX `--` separator was closed on for the same reason. Both
  are covered by a test of the conventions a person types without reading anything.
- **`forecast` called an update a change when the world already matched it.** Its own
  per-attribute predictions said otherwise on the same page.
- **`suggest` said "never gates" one line above constraints that gate.** Pasted as hard —
  the default — the recommended constraints take a PROVEN contract to BLOCKED, because a
  hard constraint over an attribute the candidate does not declare verifies unknown. The
  header now says that, and points at `--as soft`, which adopts the intent without
  blocking and was never mentioned.
- **A partially-covered cost estimate read as a central figure.** Every capability without
  a declared cost still costs money, so the number can only be wrong toward cheaper. It
  now reads as a floor when the basis is partial, and stays an estimate when it is not.
- **Posture recipes could not be followed to the end**, and `anchor` and `repair` demanded
  a provider they never use — both fixed, along with usage lines that omitted a flag their
  verb requires.

- **A silent operand could still be ignored on a fully converged deployment.** The
  guard that refuses an implementation operand no driver reads was made to iterate
  capabilities rather than actions, precisely so a converged deployment would be
  covered — and the compiler returned `nothing-to-change` sixty lines before reaching
  it. A partially converged run was covered; a fully converged one, the reported case,
  was not. The k8s driver separately declared no operands at all and so qualified for
  an exemption written for the test double.
- **Adoption bound a resource without owning it, so retiring it failed.** Ownership is
  stamped by a separate claim, which the compiler emitted only on the create/update
  path. Following the documented sequence — adopt a discovered resource, mark it
  retired, converge — produced a plan the driver refused for want of ownership
  labels. The retirement path now claims first, as the replacement path always did.
- **Adopt, converge and refresh discarded what the driver said it could not read.**
  A driver reports why an attribute could not be measured; three callers dropped it
  into `_`, including the scheduled refresh agent whose whole purpose is keeping proof
  honest. Adopt also now names each attribute it recorded as intent rather than
  measurement, so a capability confirmed against reality and one taken on faith no
  longer read the same.
- **`forecast` called an update a change when the world already matched.** Its
  per-attribute predictions said otherwise on the same page. A plan overtaken by
  reality now forecasts no effect, as a create against a bound capability already did.
- **The CLI absorbed an unknown flag as a positional argument.** A misspelled or
  removed flag was silently ignored along with its value, so a run could answer a
  question it was never asked. Unknown flags are now an error. **This is a behaviour
  change**: an invocation carrying a stale flag exits 1 instead of proceeding.
- **`anchor` and `repair` demanded a provider they never use.** Both are pure ledger
  operations and both are recovery verbs, wanted when a ledger is damaged and the
  operator may not know which cloud it describes.
- **Posture's remediation recipes could not be followed.** The class an operator lands
  in immediately after adopting carried no recipe at all; the recipes that existed did
  not say to pass `--contract` when re-checking, so a successful audit stayed
  invisible; and the adopt recipe omitted `--provider`, which the verb requires.

- **Three Kubernetes services could not be adopted, and the refusal blamed the wrong
  thing.** The driver kept a hand-coded list of seven services beside a mapping
  registry that knew ten. Every write verb checked the registry first and returned, so
  the stale list was only ever reached on the one path that did not — the
  competing-reconciler check — where six of ten services failed, three on the list and
  three deeper on a table that knows only the four RBAC kinds. Reading was also gated
  on a WRITE-safety predicate, so `discover` enumerated an ArgoCD Application with
  measured values while `observe` refused the same service as unknown, in one run.
  Found on a live k3d cluster; reads now ask the registry and writes keep the
  write-safety check, with a refusal that says *observed but not written* instead of
  *unknown service*.
- **Flux published a repository NAME where the contract promises a URL.** The GitOps
  capability exists to be controller-neutral, and its `source.repoURL` says which repo
  governs a cluster. ArgoCD emitted a URL; Flux emitted `spec.sourceRef.name`, marked
  `measured`. Both the mapping and the vocabulary documented the divergence, which
  made it honest prose over a broken contract — the values are not comparable, and a
  name is not provenance, since two clusters can each hold a `GitRepository/platform`
  aimed at different repositories. Mappings gained one declared op, `resolve-ref`: a
  second read, named in the document rather than hidden in Go, with the referent's
  schema folded into the drift fingerprint so the remote half cannot drift unnoticed.
- **Adopt said nothing about what it could not confirm.** With a readable attribute
  that differed, adoption refused; with the same attribute unreadable, it succeeded in
  silence — the weaker evidence bought the friendlier outcome. The ledger was always
  honest (`candidate-declared`, never `measured`), but `"status": "adopted"` read the
  same either way. Adoption now names each attribute it recorded as intent, and
  carries the driver's own explanation of why it could not measure it, which it had
  been discarding.

- **"nothing was changed" is no longer printed when an outcome is UNKNOWN.** A create
  whose result was unknown summarised as "0 of 1 actions applied — nothing was
  changed" while the resource had been created. Three states, not two: applied / not
  applied / NOT KNOWN, and the third may not be dressed as the second.
- **An unknown `implementation:` operand is refused on a CONVERGED capability too.**
  The refusal shipped in v0.1.4 walked the ACTION list, so it applied at the moment a
  resource was created and at no moment after — which is most of a deployment's life.
- **`plan`'s summary names the actions.** It printed one line per converged no-op and
  nothing else, so a plan that CREATED a resource summarised as "nothing to do".
- **A sealed zero-action plan validates.** The compiler seals one deliberately when a
  capability is blocked or unverified; the validator refused it, so converged
  infrastructure exited 2 — indistinguishable from a real refusal.
- **A list the vocabulary marks `unordered: true` is a set.** Declaring the same
  regions in a different order than the cloud returns them was refused as a lie.
  Canonicalized at load, in both implementations, so declared and observed compare
  equal everywhere with no second meaning of equality.
- **The reachability probe skips a deliberately private edge.** It measured the
  ORIGIN behind a CDN and reported a correct 403 as a blocked run.

### Added

- **The vocabulary's `mappings:` name every provider the drivers serve.** Twenty-nine
  (capability, provider) pairs were realised by a driver and documented nowhere —
  including `dns.record`, `network.loadbalancer` and `observability.changefeed` on all
  three clouds. Each was written by READING the driver rather than from memory,
  because a mapping is treated as authoritative when a driver and an operator
  disagree. Every one came out longer than a summary would have been, and the extra
  length is always a limit: first-value-only DNS targets, a StorageQueue-or-nothing
  destination, config-intent where a summary would have claimed a measurement, and a
  `"global"` sentinel no cloud API returns.
- **The mutation meter covers this cycle's bugs.** It had run on every push since it
  became a CI job while its newest mutant stayed a dozen entries behind. Extending it
  found a real hole on the first run: a fix's absence branch was tested and its
  read-failure branch was not.

### Fixed
- **Artefacts that did not know the Kubernetes driver exists.** The generated
  cross-cloud parity matrix reported three capabilities as built by nobody while they
  ship in `internal/k8s` (`cluster.namespace`, `compute.quota`, `gitops.application`);
  the README and the docs site never mentioned the driver at all; the driver-authoring
  guide described only the hand-written mode, so a reader adding a Kubernetes service
  would write Go where the path is a mapping YAML. Each corrected at its source.
- **`observe` could not reach the Kubernetes driver.** Its provider switch had no `k8s`
  case, so a capability could be created, updated, claimed, probed and retired on a
  cluster and never read back — the gap the observe-completeness gate forbids inside a
  driver, sitting at the CLI seam between them.
- **The CLI help under-advertised five verbs.** `adopt`, `resume` and `probe` offered
  `fake|gcp` while accepting five providers; `apply` and `converge` omitted others.
- The README's own maturity summary had drifted both ways: it under-claimed Azure
  (which closed the loop on 2026-07-24) and omitted the production incident that
  `docs/MATURITY.md` records in full.

### Added
- **The record now checks itself.** Decision numbers must be unique; every decision
  cited from the source, from `docs/MATURITY.md`, or from the record's own
  cross-references must resolve. Three entries had been lost in cross-branch conflicts
  with their citations still live — each now carries a stub saying what was lost rather
  than inventing the prose back.

## [v0.1.5] - 2026-07-30

Supersedes **v0.1.4**, which was tagged from a commit whose `make check` was RED and
therefore produced no artifacts: two doc gates failed because the tag was cut from
`master` while the work had been verified on a feature branch whose conformance suite
holds seven more cases. Same contents, green gate. See D496.


### Security
- **Ownership sweep across every mutating verb, on all four drivers** — create,
  update, delete and the intrusive probe, asked as a CLASS rather than per driver.
  **25 live defects found and fixed**, each pinned by a test that fails without the
  fix: creates that could mint a second billed resource on a re-run; deletes that
  destroyed a resource on nothing but a providerId (a custom role definition, a
  role assignment, an Activity Log export, five AWS services whose provider offers
  no tags); an update that replaced a stranger's whole budget definition; a
  Kubernetes create whose server-side apply stamped our ownership labels onto a
  foreign object, after which every later ownership check agreed it was ours.
- **The estate boundary** (project / subscription / account), previously a
  near-universal convention nobody asserted. Ownership labels and tags cannot
  answer it — they are identical in every estate a runtime manages — so a
  providerId naming another estate passed the ownership check. Three Azure deletes
  parsed the subscription and discarded it, silently retargeting the delete at the
  same name in OUR subscription.
- **S3 refuses a compliance hold up front** (Object Lock in COMPLIANCE mode),
  parity with the GCS twin; GOVERNANCE deliberately still deletes.
- Supply chain: every GitHub Action pinned to a commit SHA and **verified against
  its tag on a schedule** — two workflows holding cloud credentials were still on
  mutable tags. The release now proves its own rebuild is byte-identical and runs
  the credential-free half of the pre-ship gate.

### Added
- **Class gates ("registers")** as the standing shape for cross-driver properties:
  every service carries a decision — driven, exempt-with-re-derived-evidence, or
  on a ratchet that may only be paid down — so a new service cannot arrive
  unasked. Two meta-gates sit above them, deriving from the source which VERBS and
  which DRIVERS anyone has questioned, because the update register found two
  defects on a surface nobody had thought to ask about. The idiom and the rules it
  cost to learn are written down with the rest of the testing strategy.
- **The gates that existed and never ran now run**: the public export (whitelist,
  sanitizers, negative-space audit and a standalone `make check`), the mutation
  meter, and the strict docs-site build are CI jobs; the credential-free half of
  the mandatory pre-ship gate runs inside the release, which also states the
  credentialed half that remains manual.
- **Invariant 4 is pinned**: the operator set is closed, not merely agreed between
  the two implementations — agreement permitted growth, which is what the
  invariant forbids.
- **Post-apply reachability probe** on all three clouds (AWS CloudFront/Function
  URL, GCP Cloud Run, Azure Container Apps): after a public edge is provisioned,
  a real HTTPS GET measures whether it actually serves, four-valued — a 403 or an
  unreachable edge is never reported as clean success, and an unreachable-from-here
  is never mistaken for a denial. `converged` stops meaning "APPLIED but silently 403".
- **API-drift detection**: a deterministic requirement-invariant registry (the
  known "provider X requires Y since date Z" facts, each bound to a build-failing
  regression guard) plus daily AWS/GCP public-edge functional canaries that
  converge a real edge and read the outcome — catching a silent provider behaviour
  change before it reaches a user.
- **CDN custom domains** on AWS CloudFront and Azure CDN (aliases + viewer
  certificate), and a **safe per-origin cache default** (a dynamic origin is not
  cached — no stale/cross-user responses).
- **Serverless-to-database wiring**: Lambda VPC-attach + environment operands, an
  Aurora/Cloud SQL connection-endpoint output, and CloudFront+OAC → IAM Function
  URL so a public serverless front needs no anonymous exposure — all wired by
  `$ref`, not hand-pasted literals. Adopt→**claim** for Lambda (brownfield
  takeover without delete+recreate).

### Fixed
- An unknown `implementation:` operand is now **refused at compile** (`unknown-operand`)
  instead of silently dropped — a resource that quietly ignored a declared operand
  was the cardinal trust failure this closes. (Corrected in D530: as shipped in
  v0.1.4 this held only for capabilities WITH an action, so a bound, converged
  capability could still carry an ignored operand. The guard now walks capabilities.)
- Advisory attributes (e.g. `cost.monthly`, forecast-only) no longer block an
  otherwise-legal in-place update.
- AWS Lambda joined the `resume` reconciler — a killed mid-create no longer leaves
  the ledger permanently stale.
- Serverless idempotency-token and provider-requirement gaps (scheduler
  `ClientToken`, backup-vault `$ref`, the Oct-2025 dual-action Function-URL grant).

## [v0.1.3] - 2026-07-19

### Added
- **Breadth drivers** across AWS, GCP and Azure (~130 service mappings) with a
  cross-cloud parity program: honest per-cloud gaps, pure mapping cores + golden
  and `httptest` tests, driver certification (`provider.CertifyDriver` and the
  adversarial `CertifyDriverNet` honesty harness).
- **Evidence that travels**: detached Ed25519 event/snapshot signatures and
  portable evidence **capsules** — a receiver verifies one capability's subchain
  with no ledger and no groundhold deployment; the tail **anchor** counters omission.
- **Presentation layer**: a closed banner vocabulary, shape-first glyphs,
  refusal-is-not-failure, the stderr/stdout channel rule; `explain` for any error
  code or vocabulary path.
- **Outcome probes**, **posture** classification, **refresh**, **crawl**,
  disaster-recovery **restore/merge** from capsules, and a **manifest anchor**
  that closes the per-capability-forest tamper gap.
- Authoring boundary: the `no-assumed-hard-basis` gate a contract can arm so a
  hard constraint may not seal on an assumed value (the verifier still only
  reports the basis — policy gates).
- Developer guides: authoring a driver (`spec/providers/AUTHORING.md`) and a
  vocabulary (`spec/vocab/AUTHORING.md`); a `NOTICE` and a structured
  `docs/THREAT_MODEL.md`.

### Changed
- Permission preflight (the plan declares per-action permissions; `apply` checks
  the acting identity before the lease).
- Repair/anchor/deposed/concluding-updates; two early adversarial review rounds
  hardened the executor and ledger (lease-clock, deposed safety, deletion-
  protection fail-closed, resume identity, providerId path validation).

### Security
- An adversarial-hardening series closed a recurring fail-open / fabrication /
  nondeterminism class, each pinned by a fails-without-fix case:
  ledger hash-chain + replay (forest-anchor, snapshot projections, diagnosis);
  compiler determinism; capsule/signature/restore forgery axis;
  observe/probe (future-dated fresh-read, evidence-bar enforcement, per-source
  retention); brownfield unadopt (authorship-claim clearing, origin/pending
  gates); converge destructive-plan fail-closed; presentation banner honesty.

<!-- On each tagged release, move Unreleased items under a version heading with
the date, and start a fresh Unreleased section. -->
