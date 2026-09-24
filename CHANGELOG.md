# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

## [2.0.17] - 2026-09-24

- Seller ids are matched case-insensitively in the stream scanner. A file
  publishes `6tFvXWWAp9RZaZhG3` while the identifier is normalised to lower
  case, so an exact byte search missed the record and reported it absent.

## [2.0.16] - 2026-09-24

- Very large sellers.json documents are kept as a local copy (one download a
  day, refreshed when possible, stale copy used if a refresh fails) instead
  of a 104 MB transfer per seller. That was slow, easy to time out, and the
  cause of a lookup reporting "absent" when the transfer had merely failed.
  Set `PAYTRACE_SELLERS_CACHE` to move it.

## [2.0.15] - 2026-09-23

- A publisher account now matches whatever spelling the sellers.json uses.
  ads.txt writes `pub-1234…`; a file may publish the bare digits or
  `ca-pub-…`, and an exact string comparison reported an account that IS in
  Google's file as "checked and absent" — a miss presented as a finding.
  Only full 16-digit publisher ids are treated as equivalent to their bare
  digits, so `pub-1` cannot match a seller whose id is literally `1`.

## [2.0.14] - 2026-09-23

- The archived sellers.json search is now opt-in (`resolve_seller(...,
  archive=True)`). Operators copy ads.txt files wholesale, another operator's
  lines included, so an absent account may never have existed in that ad system
  — and searching the archive for each of 35 declared accounts costs a CDX
  query plus snapshot fetches on a service that is slow and often times out.
- `sovrn.com` maps to `https://lijit.com/sellers.json`; Sovrn does not host
  sellers.json on its own domain.

## [2.0.13] - 2026-09-23

- A seller missing from the live sellers.json is now looked for in archived
  copies of that same file. Publishers rarely prune ads.txt; ad systems prune
  sellers.json regularly, so an account declared in ads.txt but absent from the
  current document is usually one that WAS there. Up to three snapshots are
  tried, newest first, and the record carries its snapshot URL as its source so
  the report shows it as evidence of a past relationship.

## [2.0.12] - 2026-09-23

- "Checked and absent" is no longer filed as a block. A sellers.json that was
  read successfully and simply lacks the seller is a negative RESULT, not a
  failed retrieval: counting it inflated `collection_blocked`, forced the run
  INCOMPLETE, and produced one summary category per byte count
  ("streamed 101970 byte (2), streamed 3168 byte (1), ..."). It was also
  appended to a throwaway list, so the note vanished entirely.

## [2.0.12] - 2026-09-23

- A document that was streamed and simply lacks the seller is now reported as
  a COMPLETED check with a negative result, not a blocked retrieval. Filing it
  under blocked inflated the blocked count, forced the result INCOMPLETE, and
  blurred the distinction between 'could not check' and 'checked, not found'.

## [2.0.11] - 2026-09-23

- A known sellers.json location is now the only one tried. The spec's default
  was appended after it, so every Google seller also fetched
  `https://google.com/sellers.json` — a URL that does not exist and that
  Google's robots.txt disallows — producing two futile requests and two blocked
  entries per seller that buried the real diagnosis.

## [2.0.10] - 2026-09-23

- A response that arrives and is unusable is now recorded. `if not r or
  r.status != 200: continue` skipped 403s, 429s and error pages in silence, so
  a refused candidate looked exactly like one that was never tried: the known
  location for Google's sellers.json appeared nowhere in a run — not as
  evidence, not as a block, not as an error. Each attempt now reports its
  status and body size, and a streamed document that lacks the seller says so.

## [2.0.9] - 2026-09-23

- Transport failures are no longer silent. `except httpx.HTTPError: return
  None` discarded every timeout, reset and read error without a trace, so a
  failed retrieval was indistinguishable from one that checked and found
  nothing. Two attempts on a 104 MB sellers.json disappeared this way and the
  run reported no payee and no reason.
- Scan mode uses a timeout suited to a very large body (at least 300s); the
  ordinary 20s is sized for a document.

## [2.0.8] - 2026-09-23

- The streaming fallback now also runs when the ordinary read fails outright,
  not only when it is truncated. A 104 MB sellers.json that timed out fell
  through to the next candidate — for google.com that is
  `https://google.com/sellers.json`, which robots.txt disallows — so the payee
  was never named and the run only reported a blocked URL.

## [2.0.7] - 2026-09-23

- A disclaimer is no longer read as a relationship. A viewer site's terms page
  says "not affiliated with Instagram, Meta Platforms, Inc." to DENY the
  connection; the name was extracted without its sentence, so the denial became
  evidence of the link and Meta was reported against the site at
  STRONG_EVIDENCE. Names inside denial and trademark phrasings are skipped.

## [2.0.6] - 2026-09-23

- A truncation recovered by the streaming fallback is no longer reported as a
  blocked retrieval. It inflated `collection_blocked` and reported the run
  INCOMPLETE for a gap that had been filled.

## [2.0.5] - 2026-09-23

- A company name can no longer be assembled from page furniture. HTML tags were
  flattened to spaces, so the entity pattern spanned unrelated elements and a
  contact form's labels plus a footer suffix produced
  `org_name:Name Email Message Inc` — reported as if the site had named its
  operator. Tags are now a boundary, and candidates made only of form and menu
  words are rejected.

## [2.0.4] - 2026-09-23

- sellers.json documents larger than the body cap are now streamed and scanned
  instead of truncated. Google's is 104 MB uncompressed, so the payee behind any
  Google-monetised site could never be named — the ad system serving most
  ad-funded sites. Only the matched record is kept; the retrieval stays
  evidenced by a byte count and a SHA-256 taken over the stream.
- Scan-mode retrievals bypass the cache, which would otherwise serve the
  truncated copy left by an earlier ordinary fetch.

## [2.0.3] - 2026-09-23

- One AdSense payee is now one node. `ca-pub-N` in page source and `pub-N` in
  ads.txt were captured in different shapes by different collectors, so a single
  account became two graph nodes with its evidence divided between them — on a
  real domain the same ID resolved STRONG_EVIDENCE under one spelling and
  UNSUPPORTED under the other. The `adsense_pub` scheme is gone with it.
- UA identifiers now key on the account (`UA-1234`), not the property
  (`UA-1234-2`), in every collector.

## [2.0.2] - 2026-09-22

- `paytrace run` no longer crashes on a real network. It closed its HTTP
  client in a second event loop after collecting ("Event loop is closed"), so
  no output was written. Tests used mock transports, which hold no real
  connections, and never saw it.

## [2.0.1] - 2026-09-21

- Documentation, examples and test fixtures now use only placeholder data.
  2.0.0 has been withdrawn; upgrade to 2.0.1.
- Dependencies between the four packages now require `>=2.0.1,<2.1`.
- Demo fixtures now ship inside the package. Installed from a wheel, 2.0.0
  loaded the *clean* `ads.txt` in place of the poisoned one, so the
  injection demo showed no attack. A missing fixture is now an error rather
  than a silent substitution.
- Planted-identifier checks now test the identifier in question. Previously
  one planted ID inside an HTML comment made every genuine ID on the page
  read as planted, and a planted ID written as plain text passed as live
  when any real loader was present.
- `apply_assessments` now demotes GA4 and GTM identifiers. A case-sensitive
  lookup against normalised identifiers meant only all-digit AdSense IDs
  were ever demoted.

## [0.1.0] - 2026-08-17

Initial public release.

### Added
- Collectors: ads.txt v1.1 (OWNERDOMAIN/MANAGERDOMAIN), sellers.json, GLEIF,
  SEC EDGAR, UK Companies House, imprint/legal-notice scraping, self-hosted yente
- Infrastructure collectors: RDAP, crt.sh, InternetDB, mnemonic passive DNS,
  local favicon mmh3
- Reverse ads.txt/sellers.json index (`paytrace-index`) providing seller-ID and
  OWNERDOMAIN portfolio lookups
- The index satisfies `SelectivityIndex`, supplying corpus-backed evidence
  weights instead of per-case upper bounds
- `paytrace run` CLI with corpus wiring and a warning when run without one

### Added (0.2.0)
- Registry catalog: 30 corporate, land and IP registries across ~20 jurisdictions,
  with automatability marked and `paytrace registries` for querying it
- Collectors: OpenCorporates, USPTO trademark, GitHub/GitLab organizations,
  npm/PyPI/crates.io publisher provenance
- Land records: NYC ACRIS and HM Land Registry overseas-company data, entity-keyed
  by construction with natural-person owners suppressed to a terminal marker

### Added (0.3.0)
- Person-scoped collectors folded in as the `persona` extra: Gravatar, GitHub
  commit intel, PGP keyservers, holehe, WhatsMyName username expansion
- Three-key opt-in: entity_types_allowed, per-collector persona_collectors
  allowlist, and a separate allow_username_enumeration flag for enumeration
- Gated collectors are audit-logged rather than silently skipped
- `examples/end_to_end_domain.py` — full offline chain with interpretation
- `examples/reference_collector.py` — documented protocol template

### Added (0.5.0)
- Robin ingest adapter (`from_robin`, `to_handle_observations`): extracts PGP
  fingerprints, .onion addresses, Session/Tox/Jabber IDs, wallets and contextual
  handles from dark web OSINT investigations
- LLM-derived claims capped at UNCERTAIN and confined to one correlation group
- Claims marked `text_is_derived` where the source tool discarded the response body

### Added (0.6.0)
- Robin dark web OSINT ingest wired into the unified suite runner

### Added (0.7.0)
- `paytrace.agent`: agentic wrapper exposing the toolkit as tools, with
  a planner, guard layers, and a final attribution report
- Deterministic offline fixtures; ScriptedBrain default, LLMBrain optional
- Four guard layers: injection detection, field allowlisting, trust-tiered
  provenance demotion, and evidence-derived plan invariants
- `demo/run_demo.py`: four-act indirect prompt injection demo built around a
  crafted sellers.json comment field

### Fixed (0.7.1)
- Wheel build failed: a hatch force-include duplicated src/paytrace/data,
  which packages= already covers. sdist built, wheel did not -- so pip install
  from source worked and the published-wheel path was broken.

### Added (0.7.1)
- Artifact hygiene: .gitignore covering every investigation artifact class,
  scripts/pre-commit blocking them by filename and content, and an
  artifact-guard CI job failing the build if any are tracked

### Security (0.8.0)
- SSRF guard: URLs built from collected data are validated before connecting —
  scheme, userinfo, port, and DNS resolution against private/reserved ranges.
  Redirects re-validated per hop. Previously an ads.txt line reading
  `169.254.169.254, 1, DIRECT` would fetch cloud metadata.
- ReDoS: bounded the email regexes (170ms on a crafted 8KB payload)
- Path traversal: evidence body_path is confined to the package directory
- Response size cap; bandit and pip-audit in CI
- Corrected stale dependency pins (attribution-graph>=0.1.0 -> current)

### Changed (0.8.0)
- README rewritten: reference tables and commands, rationale moved to METHOD.md
  and docs/adr/

### Changed (0.9.0)
- adtx-attribution renamed to **paytrace**. Module `paytrace`, CLI `paytrace`
  and `paytrace-index`. The old name was clumsy and no longer accurate — the
  package covers registries, land records, code hosts and dark web ingest.

### Added (0.9.0)
- `attribution ask` / `attribution_suite.Investigator`: LLM orchestrator across
  the whole toolchain. Routes by subject type, runs the right packages, writes
  the report. Falls back to a deterministic planner without an API key.
- Name-keyed searches on private individuals refused before any I/O

### Security (0.10.0)
- **Correlation-group inflation fixed.** Cosmetic variants of one identifier
  (case, zero-width marks, homoglyphs, confusable punctuation) produced separate
  correlation groups, turning one observation into several. Measured: 4 groups
  and an ATTRIBUTED band from a single fact. Identifiers now normalize on
  construction and group labels canonicalize in scoring, so the defense is
  structural rather than dependent on each collector.
- Person-search refusal is now case-insensitive and normalizes its input — a
  capitalized "Who Is" previously walked past it.
- Subject routing normalizes the question; a zero-width space in a domain no
  longer defeats it.

### Added (0.10.0)
- `obfuscation` module: detects and folds zero-width, bidi, homoglyph,
  confusable-punctuation, compatibility and control-character techniques
- Obfuscation is recorded, never silently repaired. `Identifier.observed_as`
  keeps the source form without affecting keys or equality.
- Reports gain an Obfuscation section separating deliberate techniques from
  incidental whitespace
- 111 adversarial tests across the four packages, run as their own CI job

### Changed (0.11.0) — DIRECT is no longer treated as evidence
Networks hand publishers a block of ads.txt lines to paste, so a DIRECT label
may describe the publisher account, the network one layer up, or a partner two
layers up. Previously every DIRECT and RESELLER record entered at STRONG.

- New `adstxt` module classifying each account: publisher_account,
  likely_owned, intermediary, reseller_chain, boilerplate, unknown
- Reliability now set by class. Boilerplate carries **zero** weight — a line on
  40,000 domains is not weak evidence, it is no evidence.
- Without a corpus every account is `unknown` rather than optimistically STRONG
- `key_accounts()` reduces several hundred records to the one to five that
  identify the file
- `compare_domains()` separates shared templates from common control by
  reporting overlap before and after boilerplate removal
- Template fingerprinting: byte-identical pastes flagged outright
- Portfolio expansion refuses to pivot on a boilerplate account
- `cid` (TAG-ID) captured and indexed; app-ads.txt parsed alongside ads.txt
- Index gains account_holders (splittable by relationship), domains_for_cid,
  boilerplate_accounts, domains_sharing_fingerprint
- `paytrace keyaccounts <domain> --index db`

### Fixed (0.12.0) — sellers.json lookup failed silently for Google
Three compounding bugs, all hitting the ad system that names the most publishers:

1. **Wrong location.** Built `https://{adsystem}/sellers.json` unconditionally.
   Google publishes at storage.googleapis.com/adx-rtb-dictionaries/sellers.json.
2. **File too large.** Google lists every transparent AdSense publisher; the
   response cap truncated it and json.loads then failed on the fragment.
3. **Seller names typed as organizations.** Individual AdSense publishers are
   natural persons; routing them to corporate registries produced false dead ends.

Together these meant AdSense publisher names — the strongest single attribution
signal available — never resolved. Found by running against a live domain.

### Added (0.12.0)
- `sellersjson` module: location map, streaming seller lookup that works on
  truncated files, natural-person name classification, sole-operator detection
- `ext` and other publisher-supplied fields preserved as untrusted extras

### Added (0.13.0) — network and content fingerprinting
- `fingerprint` module: DNS resolution with CDN-range detection, response IP,
  SHA-256 content hash, favicon mmh3, and SimHash
- **Structural SimHash** hashes the HTML tag sequence with text stripped. Exact
  hashing sees two different documents and text SimHash sees different content;
  structural SimHash sees one template. That is what identifies a rebranded
  portfolio page. Measured on viewer-site.example: text distance 22, structural
  distance 4 between / and /mystalk/.
- CDN edge addresses are demoted, not dropped: a reviewer must be able to see
  the origin was concealed rather than assume it was never checked

### Added (0.14.0) — mandated-disclosure collectors
Closes the structural gap found by two live runs that produced an email and no
operator name. A review showed five identifier kinds emitted and never accepted
as input; `URL` held the browser-extension IDs, which were extracted and
discarded.

- `collectors/disclosure.py`: Chrome Web Store, Edge Add-ons, Firefox AMO,
  Google Play, Apple App Store, and the US Copyright Office DMCA
  designated-agent directory
- `extract_store_identifiers()` pulls store links from markup; the analytics
  collector now emits them so the pivot has an input
- Publisher names classified as person or organisation before typing
- `WELLKNOWN_SIMHASH_BITS = 48` recorded: well-known.dev SimHash values are not
  comparable to ours by Hamming distance

### Fixed (0.14.0)
- `dict.fromkeys(...)[:n]` raised KeyError — dicts are not sliceable

### Added (0.15.0) — expansion from a resolved name
The investigation stopped where it should start. A review found `PERSON_NAME`
accepted by one collector (sanctions screening), and `sellers_for_name` existed
in the index with nothing calling it.

- `enrich.expand_from_name()`: reverse sellers.json by name, document search
  across attributed properties, name-variant generation (diacritics, case,
  family-name-first ordering), handle candidates
- Routes selected by entity type; corporate registries marked *not applicable*
  for a natural person rather than run and reported as empty
- `person_name_routes` collector (npm author index); DMCA agent now accepts
  `PERSON_NAME`
- Not-checked recorded as an absence claim at zero weight, so a person missing
  from GLEIF never reads as a finding

### Changed (1.0.0) — cross-package consolidation
Reverification across all four packages found three architectural faults that
only appear at the seams:

- **Duplicated name variation.** `attribution_graph.translit` produced 400
  matching forms; `paytrace.enrich` had its own producing 7, overlapping on 1.
  A lookup silently using the weaker set missed records. paytrace now delegates
  to the core, which gained `lookup_variants()` — bounded, ordered by transform
  depth, and restricted to lookup-safe rules (7 of 23). Matching still casts the
  wide net; querying spends a request per form.
- **Handle generation lived in the ad-tech package.** Moved to
  handle-correlation, where handle formation is the subject. paytrace
  soft-imports it.
- **Two incompatible fetcher protocols.** Collectors use async `get()`;
  agent tools use sync `get_text()`. Assuming either raised AttributeError
  mid-run and lost the investigation. Both are now supported and
  capability-checked; unifying them is tracked as an open item.
- Index capability is checked, not assumed — any object may be passed as one.
- Name expansion wired into the suite orchestrator.

### Added (1.1.0) — third-party lookups and specialist registries
- `reverse_publisher_id`: publisher/analytics ID to domains via DNSlytics and
  SpyOnWeb. paytrace's central pivot no longer requires a corpus you built.
  Scored below a corpus lookup: these services assert results without exposing
  their method or coverage.
- `icij_offshore_leaks`: offshore entities, officers and intermediaries, with
  ICIJ's "not evidence of wrongdoing" qualifier carried into every claim
- `cninfo_disclosure`: Chinese listed-company filings
- `business_directory`: Infobel and Manta, corroborative only
- `chain_activity`: Bitcoin and Ethereum via maintained explorers; records that
  on-chain data never establishes who controls an address. Monero reported as
  unqueryable by design.
- `NOT_AUTOMATED` records why BlackBookOnline, OpenLinkProfiler, DNSDumpster,
  WIPO PCT states and blockexplorer.com are excluded

### Added (1.2.0) — surface harvesting completes the pivot
The frontier re-collected discovered domains but had no collector to mine them.
`surface_harvest` runs on every domain the frontier reaches and extracts author
names, WordPress logins, mailto/body/comment emails, gravatar hashes, Google
Docs links, service IDs, HTTP-header fingerprints, and — where the operator
misconfigured — exposed `.env`, `.git/config`, WP REST users, and WebFinger.

- `SERVICE_ID` identifier kind added and made pivotable via reverse lookup, so a
  shared Disqus/Intercom/Crisp ID clusters an estate rather than dead-ending
- Fixed a `dict.fromkeys(...)[:n]` slice bug (dicts are not sliceable) — the
  second occurrence of this pattern, now absent across all packages
- Leaked credentials are flagged but never stored as values

### Added (1.2.0) — the pivot loop
The seed domain is often a dead end; the identity lives on a sibling found
through shared infrastructure. This closes that gap.

- `extract_artifacts()`: deep page-body extraction — WordPress authors, Gravatar
  hashes, Google Docs/Drive IDs, OAuth emails, git identity, per-account service
  IDs, WebFinger, HTML-comment leaks, body names, response headers. Handles
  quoted and unquoted HTML.
- `pivot_expand()`: fans from the seed to siblings via shared analytics/service
  IDs, re-mines each, repeats within a hop and domain budget, decay-weights by
  distance. CDN IPs and low-selectivity IDs never seed a pivot.
- `probe_sensitive_paths()`: opt-in, audit-logged probing of /.git/config,
  /.env, /wp-json/wp/v2/users and similar. Off by default; active recon.
- Wired into the suite orchestrator: a domain investigation pivots to siblings
  before resolving.

### Fixed (1.2.0)
- Analytics-ID case mismatch in the sibling lookup: a lowercased GA4 ID from a
  page now matches a corpus keyed on the original case.

### Added (1.2.0) — deep artifact extraction and the sibling pivot
The seed often does not name its operator; a sibling does. This closes the gap
between collecting on siblings (already supported) and extracting the artifacts
that make a sibling worth reaching.

- `deep_artifacts` collector (priority 1): HTML comments, meta author, Gravatar
  hashes, 12 service-ID schemes, Google Docs/Drive links, OAuth client IDs,
  staging subdomains, WordPress user enumeration, WebFinger, humans/security.txt,
  response-header fingerprints
- Exposed `/.env` and `/.git/config`: exposure recorded at zero weight and
  flagged for disclosure; only non-secret identifiers extracted; secret values
  never stored
- `gravatar_hash()`: links a hash on one page to a candidate email on another
  without either page revealing the address
- Engine gains `PIVOTABLE_KINDS`: only kinds that open a new surface re-enter
  collection, so the sibling fan-out stays on identifiers that carry the case

### Added (1.5.0) — egress control and non-uniform registers
- `egress.py`: proxy support for Oxylabs, Bright Data, Smartproxy, NetNut, Zyte
  and any generic HTTP/SOCKS endpoint. Credentials from the environment only,
  redacted from every manifest and log.
- Exit country recorded per capture. A capture without its egress is not
  reproducible: a reviewer elsewhere cannot tell whether the page changed or the
  vantage point did.
- `GeoDivergence`: one URL from several exits, compared. Divergence means the
  operator represents itself differently by region; both captures preserved.
- `verify_egress_country()`: a proxy that fails open sends traffic from the
  analyst's own address, and learning that from the manifest afterwards is too
  late.
- Residential and mobile exits flagged as consent-sensitive in the case file,
  manifest and declaration draft.
- Catalogue extended to 43 registers with `federation_of`,
  `requires_local_egress` and `language`. The UAE is modelled as seven separate
  authorities; the old single "UAE free-zone registries" row is removed, because
  flattening a federated jurisdiction produces confident false negatives.

### Fixed (1.6.0) — transport defects found in review
- **Response cap did not work.** `r.content[:max_bytes]` materialises the whole
  body first, so a 5GB response exhausted memory before the slice applied. Now
  streams and stops reading at the cap, after transfer decoding.
- **Egress did not control transport.** EgressPool sat beside a single client
  that never used it, so the manifest would have recorded a vantage point no
  request used — fabricated provenance. Fetcher.client_for() now builds one
  proxied client per egress; a misconfigured egress raises rather than falling
  back to direct.
- **Cache key omitted the egress**, so a US capture could serve a request that
  asked for a DE vantage point.
- Agent delegates seller-name classification instead of hard-coding ORG_NAME.
- Exception taxonomy: EXPECTED_FAILURES vs internal defects, with strict mode.

### Fixed (1.7.0) — re-audit criticals
- **Capture recording is a transport invariant.** Every network attempt emits a
  capture, including refusals and errors.
- **Fetch policy is enforced**, not merely constructed: robots_policy in a case
  file previously bought nothing.
- **Budget binds every physical request** including redirect hops; max_requests=1
  with a 302 chain completed at count=2.
- Resolver injectable, so transport tests are deterministic.

### Fixed (1.8.0) — self-audit and release-audit follow-ups
- **Capture collector identity.** Every capture recorded collector="fetcher":
  _record_evidence read an attribute no production code set. Now an async-safe
  contextvars.ContextVar, wired through Engine, so concurrent collectors are
  attributed correctly. attribution-graph imports it lazily so the
  no-network-IO boundary is preserved.
- Public surfaces no longer promise calibrated probability; METHOD.md band
  table and handle-correlation sample output updated.
- README version strings point at CHANGELOG rather than being hand-maintained.
- Release workflows validate that the tag matches the packaged version.
-  states that it is collector-only and provides none of the
  evidence, policy or egress guarantees of .

### Added (1.9.0) — committed adversarial example
- `adversarial/`: the crafted sellers.json as real files, not a Python string.
  clean and poisoned differ by exactly one publisher-supplied `comment` field,
  so the attack is isolated and diffable without running anything.
- Before/after reasoning traces committed: TRACE_clean, TRACE_naive,
  TRACE_defended, TRACE_diff.
- `capture_traces.py --check` runs in CI. A committed trace that no longer
  matches behaviour documents a system that does not exist.
- Fixtures load the committed artifacts rather than reconstructing the payload,
  so the published example and the tested behaviour cannot drift.
- Plan audit no longer claims "signature of a hijacked plan" for pivots the
  planner simply did not reach; an audit that over-reports is one nobody reads.

### Known limitations
- `is_confidential: 1` sellers expose only `seller_type`, not entity name
- EDGAR full-text endpoint is undocumented and unversioned
- Imprint parsing is regex-based over stripped HTML; treat as MODERATE evidence
