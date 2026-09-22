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

## Further reading

The method in depth — sellers.json is not always at the domain root, Expansion from a name, The pivot: the answer is on a sibling, not the seed, The pivot loop — the seed is not the answer, The sibling pivot, Egress and geography, Company registers are not uniform, Source coverage, Mandated disclosures — where the name actually is, Fingerprinting: IPs, hashes, SimHash, DIRECT does not mean direct, Build the corpus first, Replacing paid APIs, Portfolio expansion, Ingest from other tools, Agent + prompt injection demo, Person-scoped collectors — is in
[docs/GUIDE.md](docs/GUIDE.md).

## Security

- **SSRF guard.** `adsystem` comes from the target's `ads.txt`, so
  `169.254.169.254, 1, DIRECT` would reach cloud metadata. Every URL is
  validated before connecting: scheme, userinfo, port, and DNS resolution
  against private/reserved ranges. Redirects re-checked per hop.
- **ReDoS-bounded regexes**, response size caps, parameterised SQL.
- `bandit` and `pip-audit` in CI. Tests in `tests/test_security.py`.

---

## Deploying

[DEPLOYMENT.md](https://github.com/tusharkarumudi/attribution-suite/blob/main/DEPLOYMENT.md). Run investigations outside the repo:

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
