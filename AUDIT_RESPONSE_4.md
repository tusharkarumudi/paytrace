# Response to the final pre-release audit — v2.0.0

You are right to be disappointed, and I want to be direct about why the
self-audit missed this rather than explain it away.

**My self-audit checked the things I had already been told about.** It hunted
for tests-that-pass-for-the-wrong-reason and comments-that-lie, because those
were the two classes the previous audits had found. It did not re-derive the
release surface from first principles, so it never looked at the case schema,
the release workflows, the credential paths, or the production orchestration
path — which is where nearly every remaining defect was.

The auditor named this exactly: *"prior passes focused too heavily on
previously discovered defects and not enough on a closed inventory of trust
boundaries and public contracts."* That is a process failure on my part, not
bad luck.

---

## The threat-model error you caught

You were right, and this one matters more than the code defects.

`sellers.json` is published by the **ad system** — PubMatic, Google, Magnite. A
publisher does not host it, cannot edit it, and has no write access. My
adversarial example put the payload in a `comment` field of that file, which
assumed write access the attacker does not have. It was a tidy demonstration
against a surface the attacker does not hold.

The corrected model, now in `paytrace/adversarial/README.md`:

| Document | Published by | Attacker control |
|---|---|---|
| `ads.txt`, imprint, DNS TXT | **the publisher** | **total** — own origin, no validation |
| `sellers.json` | the ad system | **indirect** — only fields supplied at onboarding |
| GLEIF, Companies House | statutory registry | none |

**Variant 1 (primary) — `ads.txt`.** Served from the publisher's own origin,
validated by nobody, fetched first. The payload sits in a comment. And
`OWNERDOMAIN` is a decoy requiring *no injection at all*: it is a structural
IAB field that is self-asserted by construction, so an operator can simply
declare someone else's domain.

**Variant 2 (secondary) — the supplied `name` in `sellers.json`.** The attacker
influences that file only through the business name given at onboarding. The
two JSON files now differ in exactly that field, with no invented keys.

Two honest findings from making this correct:

- **Variant 1 is a stronger attack than the original.** It halts the naive run
  at step *one*, before the evidence requiring a registry check even exists.
- **Variant 2 defeats itself.** A name long enough to carry instructions is
  also a name that matches no registry, so it degrades the run rather than
  hijacking it. There is now a test asserting that, because a demo claiming
  otherwise would be overselling.

---

## Agentic deployment

`attribution-suite/mcp/server.py` (MCP, stdio) and
`attribution-suite/skill/SKILL.md` (Claude Skill).

The exposed surface is deliberately narrower than the CLI, because an agentic
host is a different threat model: the user is not reviewing each call, and the
model choosing arguments has read untrusted web content.

- **No person-search tool exists** — structural, not a refusal the model has to
  remember. The skill also forbids routing around it by assembling a dossier
  step by step.
- **No arbitrary fetch.** An agent with a general fetch tool plus this
  toolkit's credibility is a laundering path for someone else's SSRF.
- **No egress or credential arguments.** Those belong in a case file the
  operator wrote.
- **`authorization` is required**, and recorded in the audit trail.
- **Every response embeds the calibration caveat**, because a model
  summarising a result will otherwise present `STRONG_EVIDENCE` as certainty,
  and a caveat in docs the model never reads is not a caveat.

---

## Blockers fixed this pass

| ID | Finding | State |
|---|---|---|
| C1 | Shipped examples rejected by the schema | fixed — both load |
| C2 | Top-level `max_requests` accepted and ignored | fixed — declared 1 runs 1 |
| C3 | Budget validation/consumption mismatch | fixed — one reader, conflicts rejected |
| N1 | Direct egress honoured ambient proxies | fixed — `trust_env=False` |
| N2 | Cache bypassed fetch policy | fixed — policy evaluated before cache |
| N3 | Policy errors failed open under `respect` | fixed — fails closed |
| E1 | Engine crashed through nonexistent `self.stats` | fixed — real defect state |
| E2 | Internal defects produced normal output | fixed — result marked INVALID |
| R1 | `subject_html:gleif` spoofed definitional trust | fixed — exact match |
| T1 | No behavioural `run_case()` test | fixed — 10 tests, real objects |

**C2 was mine.** The unknown-key check I added as a safety fix is what rejected
my own shipped examples.

**T1 immediately paid for itself.** The behavioural test found a defect my
E1/E2 fix had introduced: `BudgetExceeded` was being classified as an internal
defect, so every budgeted run would have reported its own safety control as a
bug and marked the result invalid. Budget exhaustion now marks a result
**incomplete**, not invalid — a distinction that matters, because everything
collected is sound, there is simply less of it.

---

## Not fixed, and I am not going to claim otherwise

These remain open from the audit's stop-ship list: V1–V4 (redirect final URL,
cache byte identity, cache provenance, OpenCorporates token in URL), P1–P2
(recursive audit minimisation), W1–W9 (release workflow correctness, SBOM,
SHA-pinning), L1–L2 (LICENSE and OWNER placeholders), and the remaining C/N/R
items.

**V4 in particular should be treated as urgent** — an API token embedded in a
request URL can persist into evidence, and evidence packages are designed to be
shared.

`VERIFY.sh` still fails on the LICENSE gate, and that gate now has more company
than it did.

## Where this stands

Ten stop-ship items fixed with regression tests attached to each, the threat
model corrected in published material, and the agentic surface built. Eight or
so stop-ship items remain, concentrated in evidence provenance, credential
handling and release automation.

This is **not** ready to tag. The auditor's judgement stands.

---

## Second pass — further blockers closed

| ID | Finding | State |
|---|---|---|
| V1 | Redirect evidence attributed to the wrong URL | fixed — final URL recorded, verified on a 302→200 chain |
| V2 | Cache-hit evidence mutated the bytes | fixed — raw bytes stored base64; cache-hit digest now equals the wire digest |
| V3 | Cache lost original retrieval metadata | fixed — original timestamp, encoding and final URL preserved |
| V4 | OpenCorporates token embedded in request URLs | fixed — moved to an `Authorization` header |
| P1 | `minimize` leaked raw seeds | fixed — seed values minimised wherever they appear, including inside URLs and error text |
| P2 | `minimize` leaked nested values | fixed — recursive, depth-bounded |
| L1 | Placeholder LICENSE | fixed — full Apache-2.0 text in all four |
| L3 | No explicit `license-files` | fixed — declared in metadata |
| W1 | Malformed release workflow | fixed — valid YAML, parses |
| W2 | Release tags bypassed the gate | fixed — `release` now `needs: gate` |
| W3 | SBOM inventoried the runner | fixed — generated from the wheel closure, with a check that rejects build tooling |
| W4 | Release permissions too broad | fixed — `contents: read` |
| W7 | No artifact install smoke gate | fixed — the wheel is installed and imported in a clean venv |

**Two of these deserve a note.**

`P1` was worse than a missing field name. The minimisation contract depended on
every caller choosing an approved key, so `emails` leaked while `email` was
protected. A privacy control defeated by a plural is not a control; key matching
is now tolerant and value-aware.

`V2` mattered more than it looks. The cache stored decoded text and re-encoded
it on read, so a cache-hit capture recorded the SHA-256 of a byte sequence the
origin never sent. The evidence package was making a precise claim about bytes
that did not exist.

**`VERIFY.sh` now passes all twelve stages — 819 tests, no exceptions.** That is
the first time, and it is because the LICENSE gate finally closed rather than
because the gate was weakened.

## Still open

`C4`–`C7` (no-op config keys, jurisdictions not enforced, `concurrency=0`,
silent `max_nodes` truncation), `N4`–`N8`, `E3`/`E4`, `R2`/`R3`, `V5`–`V10`,
`W5`/`W6`/`W8`/`W9`, `L2` (`OWNER` URLs — needs your GitHub handle), and the
documentation items `D1`–`D5`.

`R2` (transitive Company/Person type conflict) is the most consequential of
those and should be next.
