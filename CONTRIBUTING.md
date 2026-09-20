# Contributing

## What belongs here

Collectors against **public registries, self-published files and open protocols**.
Every collector declares a `source_class`, checked against the deny list at load.

New collectors are welcome if they satisfy all of:

- **Free and keyless**, or free-tier with a documented key. No paid API in the
  critical path.
- **Legally published** — statutory registry, IAB-spec file, RFC-defined protocol,
  or a disclosure the operator is legally obliged to make.
- **Respects robots.txt and stated rate limits.** Declare the limit in
  `net.RATE_LIMITS`.
- **Sets `correlation_group` deliberately.** This is the one thing reviewers will
  push back on. If your collector emits 400 claims from one page, they are one
  group. See [METHOD.md §2.2](https://github.com/tusharkarumudi/attribution-graph/blob/main/METHOD.md).
- **Sets `reliability` honestly.** `AUTHORITATIVE` means a statutory registry or a
  cryptographic binding. Self-declared data is `STRONG` at best. Regex over
  scraped HTML is `MODERATE` or `WEAK`.

## What does not belong here

- Person-attribution collectors. The protocol is documented; the assembly is
  deliberately left to the operator.
- Data brokers, breach corpora, authenticated scraping, biometrics, location
  brokers. These raise at load and a PR removing that check will be declined.
- Anything requiring a paid API where a free source covers the same ground.

## Testing collectors

Do not hit live endpoints in CI. Record a fixture response, assert on the claims
produced — particularly the `correlation_group` and `reliability` — and add a
contract test if the upstream API is undocumented (EDGAR's full-text endpoint is
undocumented and unversioned; treat it defensively).

## Development

```bash
pip install -e ".[dev]"
pytest -q && ruff check .
```
