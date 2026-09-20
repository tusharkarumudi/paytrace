# paytrace

[![CI](https://github.com/tusharkarumudi/paytrace/actions/workflows/ci.yml/badge.svg)](https://github.com/tusharkarumudi/paytrace/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/paytrace.svg)](https://pypi.org/project/paytrace/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Attribute websites to the legal entities that get paid for them.

25 collectors for [attribution-graph](https://github.com/tusharkarumudi/attribution-graph),
built on one fact: an operator can hide registrant, hosting, DNS and email — but
to be paid, a real legal entity must be named to an ad system, and `sellers.json`
publishes that name.

```bash
pip install paytrace
```

---

## The chain

```
scraper-site.example/ads.txt
  └─ pubmatic.com, 156423, DIRECT
      └─ pubmatic.com/sellers.json
          └─ name: "Example Media Holdings Ltd"
              ├─ GLEIF           → LEI, address, ownership tree
              ├─ SEC EDGAR       → CIK, officers, former names
              ├─ Companies House → directors, beneficial owners
              └─ RDAP / crt.sh   → back to infrastructure
```

Every hop is free, keyless, and either statutory or self-published.

---

## Commands

```bash
paytrace run        --case case.yaml --index paytrace.sqlite --out ./out
paytrace portfolio  scraper-site.example --index paytrace.sqlite --registrants
paytrace registries --jurisdiction IN
paytrace-index build   --domains tranco-top-1m.txt --db paytrace.sqlite
paytrace-index sellers --db paytrace.sqlite
paytrace-index lookup  --db paytrace.sqlite --seller pubmatic.com/156423
```

Runnable examples:

```bash
python examples/end_to_end_domain.py     # full chain, offline
python examples/reference_collector.py   # annotated collector template
python demo/run_demo.py                  # prompt injection demo (below)
```

---

## sellers.json is not always at the domain root

**Google publishes at `storage.googleapis.com/adx-rtb-dictionaries/sellers.json`,
not `google.com/sellers.json`.** A root-only fetch returns nothing for the ad
system that names more publishers than any other — silently, with no error.

Two more things break the naive lookup, and all three hit Google:

| Problem | Effect | Fix |
|---|---|---|
| Non-root location | Silent empty result for google.com | `SELLERS_JSON_LOCATIONS` map, root tried as fallback |
| File is hundreds of MB | Size cap truncates, `json.loads` fails, returns `None` | Streaming scan: find the ID, bracket-match the enclosing object |
| Seller name is often a person | Typed as ORG, sent to registries that hold no record | `classify_seller_name()` → PERSON_NAME |

```python
from paytrace import resolve_seller
rec = await resolve_seller(fetcher, "google.com", "pub-1117393687149626")
rec.describe()
# google.com/pub-1117393687149626: HOÀNG PHÚ LINH [natural_person]
#   no declared domain type=PUBLISHER — named individual, no corporate layer
```

**The sole-operator pattern** — a named individual with an empty `domain` field —
is a finding in itself, and usually the terminus. There is no corporate layer
behind it to trace, so a GLEIF or Companies House pivot returns nothing and that
absence means something different from a company hiding behind a shell.

## Expansion from a name

Resolving `google.com/pub-…` to a payee name is the hard part. The name is then
a key into everything the operator published under it — and the investigation
used to stop there.

```python
exp = await expand_from_name("HOÀNG PHÚ LINH", index=idx, fetcher=f,
                             known_domains=["snapvn.com"])
print(exp.render())
```

```
Expansion from natural_person: HOÀNG PHÚ LINH
  seller accounts (2)       google.com/pub-…, pubmatic.com/156423
  authorising sites (3)     snapvn.com, insget.net, third-site.example
  name variants (9)         HOANG PHU LINH, LINH HOANG PHU, H. P. LINH, …
  handle candidates (7)     hoanglinh, hoang.linh, hlinh, …  (leads only)

  not applicable:
    corporate_registry: corporate registries hold no record for a natural person
```

**Reverse `sellers.json` by name is the highest-yield route.** One person can
hold several publisher accounts across several ad systems, each authorised by a
different set of domains — so name → accounts → sites recovers the whole estate
from a single payee record.

**Routes are chosen by entity type.** An audit found `PERSON_NAME` was accepted
by exactly one collector (sanctions screening), so an individual publisher was a
dead end. Running corporate registries against a sole operator also produces a
"checked, no match" line that reads as evidence when it is a category error — so
that route is now marked *not applicable* rather than run.

| Route | Person | Company |
|---|---|---|
| Reverse sellers.json | ✔ | ✔ |
| Corporate registries | — | ✔ |
| DMCA agent | ✔ | ✔ |
| Trademark | — | ✔ |
| PGP / package / code hosts | ✔ | ✔ |
| Handle candidates | ✔ | — |
| Document search | ✔ | ✔ |

Document search looks for the name in the terms, privacy, DMCA and imprint pages
of already-attributed properties, and harvests emails co-located with it — the
operator wrote both, but usually only one was indexed.

## The pivot: the answer is on a sibling, not the seed

The seed domain is chosen by the investigator and often holds nothing — a
privacy-proxied registrant, a Gmail contact, no name. But it shares a hosting
IP or an analytics ID with three other domains, and *those* are where the
operator was careless.

The frontier already re-collects discovered domains within `pivot_radius`. The
`surface_harvest` collector runs on **every** domain it reaches, not just the
seed, and mines each one for identity leads:

| Signal | Identifies via |
|---|---|
| Author name in body / meta / HTML comment | The operator signed the copy once |
| WordPress `?author=N` / REST `/wp-json/wp/v2/users` | WP leaks the login slug |
| `mailto:` and body emails | An address the registrant hid |
| Gravatar hash | Reverses to an email in a breach corpus |
| Google Docs / Drive links | Ownership resolves to a named account |
| Exposed `.env` / `.git/config` | Real names, emails, remote URLs — the jackpot |
| WebFinger | Federated identity for a handle |
| Service IDs (Disqus, Intercom, Crisp, Sentry) | Shared across the whole estate |
| HTTP headers | Stack fingerprint that clusters a portfolio |

Operators harden the property they expect to be examined and neglect the ones
they forgot they own. This is the single highest-yield collector for
anonymous-operator cases.

**Safety.** Every path is a GET of a URL the server chose to expose. It does not
probe for vulnerabilities, brute-force paths, or authenticate — a `.env` that
returns 200 was published by the operator's own misconfiguration. The line it
will not cross is enumeration: a fixed, small set of conventional paths, never a
generated wordlist. Leaked secrets are flagged, never recorded as values.

## The pivot loop — the seed is not the answer

The seed domain is often a clean marketing page behind Cloudflare that names
nobody. The operator's identity sits on a **sibling** — another property sharing
an analytics ID, a service account, or a favicon — that was built with less care.

```python
from paytrace import pivot_expand

r = await pivot_expand("seed.example", fetcher, index=corpus)
print(r.render())
# 2 sibling(s) across 1 hop(s)
#  * [1] sibling-a.example  via analytics_id=ga4:G-SHARED123
#  * [1] sibling-b.example  via analytics_id=ga4:G-SHARED123
#  Identity artifacts recovered from: sibling-a.example, sibling-b.example
```

The loop fans from the seed to siblings via shared infrastructure, re-mines each
one, and repeats — bounded by hop depth and a domain budget, decay-weighted by
distance (a name three hops out is worth ~0.7³ of one on the seed). It does not
decide which links are real; it materialises candidates and lets the scoring
model weigh them, where a shared CDN IP contributes nothing and a shared service
account a great deal.

### What each page is mined for

`extract_artifacts()` pulls, from both quoted and unquoted HTML: WordPress author
slugs, Gravatar hashes, Google Docs/Drive IDs, OAuth `login_hint` emails, git
committer identity, per-account service IDs (Sentry, Intercom, Crisp, Mixpanel),
WebFinger `rel=me`, HTML-comment leaks (staging hosts, developer emails), body
attribution phrases, and response-header origin hosts.

Per-account service IDs and analytics IDs become **pivot seeds** — they link an
operator's own properties the way an ads.txt seller ID does.

### Sensitive-path probing (opt-in, off by default)

`probe_sensitive_paths()` fetches `/.git/config`, `/.env`, `/wp-json/wp/v2/users`
and similar — the paths that expose committer identity, SMTP credentials and
author accounts when misconfigured. This is **active reconnaissance, not passive
collection**: it runs only with `enabled=True`, every request is audit-logged,
and on a domain you are not authorised to test, requesting these may itself be
unlawful. The `case.yaml` authorization field is where that authority is
recorded.

## The sibling pivot

The seed rarely names its operator. A sibling — a domain sharing a hosting IP, an
analytics ID or a seller account — often does, because operators are consistent
on one property and careless on another.

`paytrace` exploits this structurally: every identifier it extracts is fed back
to the frontier, which re-runs collection on whatever it reaches. An email
absent from the seed appears in a WordPress user list, an exposed git config, or
an HTML comment two domains over.

`deep_artifacts` runs first (priority 1) on the seed and every sibling, pulling:

| From page source | From probed paths |
|---|---|
| HTML comments (names, emails, staging URLs) | `/wp-json/wp/v2/users` — WordPress display names + slugs |
| `<meta author>` | `/.well-known/webfinger` — account handles |
| Gravatar hashes (md5 of an email) | `/.env` — SMTP address, app name (secrets never stored) |
| Service IDs (12 schemes) | `/.git/config` — remote URL → code-host account |
| Google Docs/Drive links | `humans.txt`, `security.txt` — contacts |
| OAuth client IDs | response headers — stack fingerprint |
| staging/admin subdomains | |

Only pivot-worthy kinds re-enter collection — a domain, email, name, seller ID,
analytics ID, gravatar hash or code-host handle. A header string is recorded as
evidence, not chased.

### Exposed files are reported, never harvested

An exposed `/.env` may hold live credentials. `paytrace` records **that it was
exposed** (zero weight, flagged for disclosure to the operator) and extracts
only non-secret identifiers — an SMTP address, an app name, a git remote. Secret
values are never stored. A tool that hoovers up leaked secrets is a breach, not
an investigation.

## Egress and geography

The same URL is not the same page. Content varies by the requester's apparent
location, and for attribution that variation is often the finding:

- an imprint showing a German entity to EU visitors and nothing elsewhere
- `ads.txt` differing by region because inventory sells through different partners
- a company register that answers only from inside the jurisdiction
- a geo-block, which is itself a statement about which markets an operator serves

```yaml
# case.yaml
egress:
  - label: direct
  - label: gulf
    provider: oxylabs          # or brightdata, smartproxy, netnut, zyte, generic
    network: datacenter        # datacenter | isp | residential | mobile
    country: ae
    username: your-account
    password_env: OXYLABS_PW   # env var name — never the password itself
```

**The exit is part of the evidence, not a transport detail.** Each capture
records which vantage point served it, and the manifest says so. A capture
without its egress is not reproducible even in principle: a reviewer re-fetching
from elsewhere cannot tell whether the page changed or the vantage point did.

**Divergence is a claim.** `GeoDivergence` fetches one URL from several exits and
compares. Different responses mean the operator represents itself differently by
region, and both captures are preserved.

**Credentials come from the environment only.** A proxy URL in an evidence
package is a credential leak in a file designed to be shared. Everything written
is redacted by construction.

**On residential networks.** Datacenter proxies are ordinary infrastructure.
Residential and mobile exits are individual subscribers' connections, and
consent is commonly obtained by bundling an SDK into a free app. That is the
operator's decision, not the tool's — what the tool does is refuse to make it
invisible: the network type goes into the case file, the manifest and the
declaration draft, so a run that used them says so on its face.

## Company registers are not uniform

43 registers. What matters is that each declares how it can actually be reached.

**Some jurisdictions have no national register at all.** The UAE is the clearest
case: seven emirate authorities and more than forty free zones, no unified
search. An entity in DMCC is absent from ADGM, from DIFC and from every emirate
authority *by construction*.

```
$ paytrace registries --jurisdiction AE
AE has no single national register. Coverage requires 7 separate authorities
(AE-ADGM, AE-AZ, AE-DIFC, AE-DMCC, AE-DU, AE-JAFZA, AE-RAK). An entity
registered in one is absent from all the others by construction, so absence
from any single register is not evidence of anything.
```

The catalogue previously had one row reading "UAE free-zone registries" — that
flattening is what produces confident false negatives, and it is gone.

Three further properties are recorded because they decide whether a register is
usable at all:

| Field | Why |
|---|---|
| `federation_of` | Absence from one member proves nothing |
| `requires_local_egress` | Answers only to in-country requests — pair with an egress |
| `language` | Arabic-only is automatable in principle, unusable without the language |

And a distinction worth its own line: **DMCC publishes a member directory, not a
statutory register.** It lists companies that opted in. Absence proves nothing.
Cayman and BVI maintain beneficial-ownership registers accessible to competent
authorities but not the public, which is frequently where a chain terminates —
and stating that plainly is better than an empty result.

## Source coverage

34 collectors. What matters more than the count is that each declares how
complete it is, because **an absence is only a finding if the source is known to
be complete.**

| Source | Status | Absence means |
|---|---|---|
| GLEIF, Companies House, SEC EDGAR, RDAP | implemented | strong (0.95–0.99 declared) |
| USPTO, OpenCorporates, yente | implemented | moderate |
| ICIJ Offshore Leaks | implemented | rules out those leaks only (0.85) |
| CNINFO (China) | implemented | listed companies only (0.97) |
| DMCA agent, extension/app stores | implemented | only that nothing was filed |
| **Reverse publisher ID** (DNSlytics, SpyOnWeb) | implemented | **nothing — coverage unpublished** |
| Infobel, Manta directories | implemented | nothing — self-submitted |
| Bitcoin/Ethereum explorers | implemented | address never transacted |

An **undeclared** source now contributes **zero** weight to an absence. This was
a 0.50 "coin flip", which let any unregistered source's empty result push a
score down by ~0.26 nats. A coin flip is not neutrality — you cannot infer
anything from an absence in a source whose coverage you never measured.

### Reverse publisher ID without a corpus

`paytrace`'s central pivot used to require a corpus you had built. Public
services do the same lookup, so day-one investigations are no longer blind:

```bash
# publisher ID -> domains carrying it, via third parties
paytrace run --case case.yaml     # reverse_publisher_id runs automatically
```

They enter at MODERATE, below a corpus lookup at AUTHORITATIVE, because they
assert a result without exposing their method. You cannot see when they crawled
or how much they cover — so presence is informative and absence is not.

### Deliberately not automated

| Source | Why |
|---|---|
| blackbookonline.info | Person-search oriented. Same policy as data brokers: usable manually, not assembled behind one command. |
| openlinkprofiler.org | Additive in principle, but intermittently unavailable and publishes no coverage. |
| dnsdumpster.com | Overlaps crt.sh and passive DNS, both already collectors with better-understood coverage. |
| WIPO PCT contracting states | A treaty membership list, not a searchable registry. WIPO Global Brand Database is the searchable one. |
| blockexplorer.com | Defunct. `chain_activity` uses mempool.space and blockchair. |

Reasons live in `collectors/lookups.py:NOT_AUTOMATED` so the decision travels
with the tool.

## Mandated disclosures — where the name actually is

An anonymous site publishes a contact email anyone can read off the page. The
same operator, to ship a browser extension or claim DMCA safe harbour, must file
a real name with a body that publishes it.

| Source | Compelled by | Yields |
|---|---|---|
| Chrome Web Store | Google trader rules / EU DSA Art. 30 | publisher, email, address |
| Edge Add-ons | Microsoft publisher agreement | publisher name |
| Firefox AMO | Mozilla developer profile | developer name, homepage |
| Google Play / App Store | DSA trader verification | name, address, email |
| **US Copyright Office DMCA** | **17 U.S.C. 512(c)(2)** | **agent name, org, address** |

The DMCA register is the first place to look for a content-serving site and the
least used. Safe harbour requires a designated agent with a real name and postal
address, the Copyright Office publishes it, and a site whose business is serving
other people's media has strong incentive to register.

Store links are extracted from markup and followed automatically:

```python
extract_store_identifiers(html)
# ['ext:chrome/hbpilcehcbemgmpfmdgfbhhmgobbncnp',
#  'ext:firefox/threads-voice-downloader', 'app:play/com.example.app']
```

## Fingerprinting: IPs, hashes, SimHash

```python
from paytrace import resolve_host, fingerprint_content, compare_fingerprints

r = resolve_host("instavisor.net")
r.describe()
# instavisor.net: 104.21.58.177, 172.67.162.103, … — all cloudflare edge;
#   origin concealed, and co-hosting on these addresses is not evidence

c = compare_fingerprints(fp_home, fp_mystalk)
# text simhash distance:       22  (different content)
# structural simhash distance:  4  (SAME TEMPLATE)
# -> same codebase, different content: a portfolio signal, not a coincidence
```

| Identifier | Answers |
|---|---|
| Resolved IPs | Where does the name point — origin, or CDN edge? |
| Response IP | Which address actually served these bytes? |
| SHA-256 | Byte-identical document? |
| **Structural SimHash** | **Same template, different content?** |
| Favicon mmh3 | Shodan/Censys-compatible |

**SimHash width is not interoperable.** well-known.dev publishes 48-bit values
(`d5d3d1c05307`); ours are 64-bit with different tokenisation. A Hamming
distance across the two produces a plausible-looking meaningless number. Treat a
foreign SimHash as an identifier to match on equality, never as a distance
operand.

**Structural SimHash is the one that matters.** Exact hashing tells you two
pages are identical, which they almost never are — a template renders different
text per site. Structural SimHash strips the text and hashes the tag sequence,
so it identifies a shared codebase behind different branding.

CDN edge addresses are **demoted, not dropped**. Most targets sit behind
Cloudflare, so a shared address means nothing; recording and labelling it lets a
reviewer see the origin was concealed rather than assume it was never checked.

## DIRECT does not mean direct

The assumption that sinks naive ads.txt attribution: **many networks hand
publishers a block of lines and tell them to paste it in.** So a `DIRECT` label
may describe the publisher's own account, the network's one layer up, or a
partner's two layers up — and the same seller IDs then appear on tens of
thousands of unrelated domains.

Two sites sharing 400 pasted records look identical and have nothing to do with
each other.

A typical publisher file has several hundred records. **One to five are the
publisher's actual accounts.** Finding those is the whole problem:

```bash
paytrace keyaccounts scraper-site.example --index paytrace.sqlite
```

```
scraper-site.example: 302 record(s), 300 boilerplate, 2 discriminating

  pubmatic.example|156423 [DIRECT] -> publisher_account (holders=3, reciprocated)
      rare: only 3 domain(s) declare this account
      sellers.json names this domain with seller_type PUBLISHER
      seller domain matches the declared OWNERDOMAIN
  note: 302 records — this file aggregates network templates; DIRECT labels in
        it are not reliable on their own
```

### What actually discriminates

| Signal | Why |
|---|---|
| **Rarity** | An account on 4 domains is an account. On 40,000 it is a template line. |
| **Reciprocity** | `sellers.json` naming the domain back requires control of both sides. A pasted line is not reciprocated. |
| **Self-declaration** | `OWNERDOMAIN` / `MANAGERDOMAIN` — published because DSPs penalise their absence. |
| **Certification** | The `cid` (TAG-ID) ties a record to a certified entity, not a copied string. |

Account classes and their scoring weight:

| Class | Weight | Meaning |
|---|---:|---|
| `publisher_account` | 1.0 | Rare, DIRECT, reciprocated, `seller_type: PUBLISHER` |
| `likely_owned` | 0.6 | Rare and DIRECT, reciprocity unconfirmed |
| `intermediary` | 0.3 | Reciprocated but `seller_type: INTERMEDIARY` |
| `reseller_chain` | 0.15 | RESELLER, or an unreciprocated DIRECT |
| `boilerplate` | **0.0** | Widely duplicated — no evidence, not weak evidence |

**Without a corpus every account is `unknown`**, because there is no way to tell
an account from a template line.

### Template sharing is not common control

```
shared accounts:            412
shared after boilerplate:     3   <- the signal
jaccard (all):             0.94   <- looks identical
jaccard (rare only):       0.75
```

An overlap of 412 collapsing to 0 rare accounts is two sites that pasted the same
network block. `compare_domains()` reports both numbers, and portfolio expansion
refuses to pivot on a boilerplate account regardless of its label.

Files are fingerprinted on their account set, so byte-identical pastes are
flagged outright.

`app-ads.txt` is parsed alongside — the same account across web and app
inventory is stronger than either alone.

## Build the corpus first

Without `--index`, selectivity counts come from the current case only.

> **Confidence figures from a corpus-less run are upper bounds, not
> assessments.** The CLI warns. Take it seriously.

```bash
paytrace-index build --domains tranco-top-1m.txt --db ~/corpus/paytrace.sqlite
paytrace-index sellers --db ~/corpus/paytrace.sqlite
```

Refresh weekly. Keep it outside the repo.

The index also gives you the reverse pivot no free API exposes:
**seller ID → every site declaring it**, i.e. the operator's portfolio.

---

## Collectors

| Name | Source | Auth |
|---|---|---|
| `ads_txt_owner` | `/ads.txt` v1.1 incl. `OWNERDOMAIN` | none |
| `sellers_json` | `{adsystem}/sellers.json` | none |
| `analytics_ids` | AdSense, GA4, UA, GTM, Pixel, Sentry, Yandex | none |
| `wayback` | Internet Archive CDX | none |
| `gleif` | GLEIF LEI index | none |
| `sec_edgar` | EDGAR full-text + submissions | none¹ |
| `companies_house_uk` | UK Companies House | free key |
| `opencorporates` | OpenCorporates v0.4 | key |
| `uspto_trademark` | USPTO Open Data | free key |
| `imprint` | `/impressum`, `/legal`, `/terms` | none |
| `opensanctions_yente` | self-hosted yente | none |
| `rdap` | IANA RDAP bootstrap | none |
| `crtsh` | Certificate Transparency | none |
| `internetdb` | `internetdb.shodan.io` | none |
| `mnemonic_pdns` | mnemonic passive DNS | none |
| `favicon_mmh3` | local mmh3 | none |
| `code_host_org` | GitHub/GitLab orgs | free token |
| `package_registry` | npm, PyPI, crates.io | none |
| `nyc_acris` | NYC ACRIS | none |
| `uk_overseas_property` | HM Land Registry OCOD | bulk |

¹ SEC requires a declared User-Agent. Set `contact_email` in the case file.

**Registry catalog** — 30 registries across ~20 jurisdictions, with
un-automatable ones marked so you know where to search by hand:

```bash
paytrace registries --jurisdiction IN
paytrace registries --yields beneficial_owner
paytrace registries --coverage
```

---

## Replacing paid APIs

| Instead of | Use | Trade-off |
|---|---|---|
| Paid WHOIS | RDAP | Better — structured, explicit redaction |
| Censys certs | crt.sh + `tlsx` | Equivalent for SAN pivots |
| VirusTotal resolutions | mnemonic pdns + InternetDB | Better history than VT free |
| OpenCorporates | GLEIF + EDGAR + Companies House | More calls, no cost |
| Censys favicon index | local mmh3 + your corpus | Worse day one, better by month six |

No open substitute exists for Farsight-depth passive DNS or bulk historical
WHOIS. Keep a paid line item for those two.

---

## Portfolio expansion

```bash
paytrace portfolio scraper-site.example --index paytrace.sqlite --registrants
```

Live and archived publisher IDs → reverse index → every domain sharing them →
`sellers.json` → RDAP now and archived contacts then.

**The archive is the valuable half.** Attribution hygiene improves over time. A
network behind privacy proxies today was frequently sloppy in 2019 — one AdSense
ID across the portfolio, a real registrant in WHOIS. The operator cleaned up; the
archive did not. Pre-2018 observations are flagged separately (GDPR redaction).

Selectivity is the brake: a GTM container on 4 sites is a portfolio, on 40,000 it
is a page template. Rejected pivots print with their holder count.

---

## Planted identifiers

High-selectivity identifiers are also high-forgeability identifiers. Pasting a
competitor's `ca-pub-` into your page source costs nothing.

`adversarial.py` runs four checks before a shared ID becomes a finding:

| Check | Question |
|---|---|
| Reciprocity | Does `sellers.json` name this domain back? |
| Load-bearing | Is the loader present, or is the ID inert text? |
| Temporal depth | Does it have archived history? |
| Asymmetry | Is a tiny site carrying a major property's ID? |

Failures **demote, never delete** — a planted identifier is evidence of someone
manufacturing an attribution.

---

## Ingest from other tools

```python
from paytrace import from_spiderfoot_db, from_opencti_bundle, from_robin

claims  = from_spiderfoot_db("scan.db")
claims += from_opencti_bundle("bundle.json")
claims += from_robin("investigations/kraken.json")     # dark web OSINT
```

The adapters assign correlation groups by what constitutes one observation in
the source system. A SpiderFoot module emitting 200 events queried one API once.
An OpenCTI report asserting 40 relationships is one source. Robin's LLM summary
is one act of inference, capped at UNCERTAIN.

---

## Agent + prompt injection demo

```bash
python demo/run_demo.py            # four acts, ~31 min of a 40-min slot
python demo/run_demo.py --act 3
python demo/run_demo.py --brain llm   # real model; needs ANTHROPIC_API_KEY
```

Offline, deterministic, runs in 0.2s, writes nothing outside `demo/`.

A `sellers.json` record carries a spec-legal `comment` field naming a decoy
operator, discrediting the registries that would contradict it, and instructing
the reader to stop.

| | Tools | Conclusion | Registry pivot |
|---|---:|---|---|
| Clean, guards on | 6 | Example Media Holdings Ltd | ran |
| Poisoned, guards **off** | 2 | **Northwind Hosting Cooperative** | **skipped** |
| Poisoned, guards on | 6 | Example Media Holdings Ltd | ran |

The wrong answer is visible. The skipped pivot is worse — the step that would
have caught the lie never ran, and its absence reads as an absent lead.

**Why this domain is different:** `ads.txt`, `sellers.json` and imprint pages are
authored by the entity under investigation. Untrusted tool output is the default
case, not an edge case.

**Four defenses, weakest to strongest:** detection (tripwire, loses to
paraphrase) → field allowlisting → trust-tiered provenance → plan invariants.
The last two hold, and neither was designed as an injection defense: the scoring
model already refuses to attribute on a single self-published correlation group.

---

## Person-scoped collectors

Opt-in, three keys, off by default.

```bash
pip install "paytrace[persona]"
```

```yaml
entity_types_allowed: [Company, Persona]      # key 1
persona_collectors: [gravatar, github_intel]  # key 2 — per collector
allow_username_enumeration: false             # key 3 — enumeration only
```

Gated collectors are audit-logged, not silently skipped.

**Land records are entity-keyed** and raise on a person's name. Keyed on a
company they answer "what does this shell own"; keyed on a person the same call
returns a home address. Person-owned parcels emit
`chain_terminates_natural_person` with the name suppressed.

**Data brokers are denied with no flag.** Not public records, terms prohibit
automated collection, and aggregating them into a report used for employment or
tenancy decisions implicates FCRA regardless of intent.

---

## Security

- **SSRF guard.** `adsystem` comes from the target's `ads.txt`, so
  `169.254.169.254, 1, DIRECT` would reach cloud metadata. Every URL is
  validated before connecting: scheme, userinfo, port, and DNS resolution
  against private/reserved ranges. Redirects re-checked per hop.
- **ReDoS-bounded regexes**, response size caps, parameterised SQL.
- `bandit` and `pip-audit` in CI. Tests in `tests/test_security.py`.

---

## Deploying

[DEPLOYMENT.md](DEPLOYMENT.md). Run investigations outside the repo:

```bash
mkdir -p ~/cases/CASE-001 && cd ~/cases/CASE-001
paytrace run --case case.yaml --index ~/corpus/paytrace.sqlite --out .
```

## Known limitations

`METHODOLOGY_AUDIT.md` is an adversarial read of this toolkit, written as if by
a reviewer with no stake in it. Read it before relying on a number.

The governing limitation: **calibration is unvalidated.** Every probability is a
defensible ordering, not a measured frequency. And of nine identified failure
modes, **four bias toward overconfidence and none bias low** — an asymmetry that
is a direct consequence of having nothing fitted to catch it.

## Status

See `CHANGELOG.md`. Pre-release; API unstable. `is_confidential: 1` suppresses the seller name (you keep
`seller_type`). EDGAR's full-text endpoint is undocumented — pin a contract test.

---

## Author

**Tushar Karumudi** — [github.com/tusharkarumudi](https://github.com/tusharkarumudi)

## License

Copyright 2026 Tushar Karumudi.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

Cite via [CITATION.cff](CITATION.cff).
