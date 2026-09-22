"""Reverse ads.txt / sellers.json index.

Solves two problems with one artifact.

**Portfolio discovery.** A forward lookup (domain -> seller_id) tells you how one
site monetizes. The pivot that matters for network attribution is the reverse --
seller_id -> every site declaring it -- which reveals the operator's portfolio.
That requires an index, because no public API exposes it in a form that is both
free and automatable.

**Selectivity.** The scoring model's evidence weight comes from how many entities
carry an identifier value. Without a corpus, a per-case index cannot tell a
seller ID held by one site from one held by four thousand, and treats both as
unique. This index supplies the real counts, which is the difference between an
upper bound on confidence and an actual assessment.

Build it once from a domain corpus (Tranco, a CT-derived host list, or your own
abuse population), refresh weekly, and pass it to the engine as the selectivity
index.

    python -m paytrace.index build --domains domains.txt --db paytrace.sqlite
    python -m paytrace.index sellers --db paytrace.sqlite --refresh
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from attribution_graph import Identifier, IdKind

# User-Agents derive from the package version so a bump can never
# leave a stale string behind. A patch bump previously left five
# User-Agents reporting the old version.
from ._version import __version__ as _VERSION  # noqa: E402
from .net import Fetcher

SCHEMA = """
CREATE TABLE IF NOT EXISTS ads_record (
    domain      TEXT NOT NULL,
    adsystem    TEXT NOT NULL,
    seller_id   TEXT NOT NULL,
    relationship TEXT NOT NULL,
    cid         TEXT DEFAULT '',
    resource    TEXT DEFAULT 'ads_txt',   -- ads_txt | app_ads_txt
    fetched_at  TEXT NOT NULL,
    PRIMARY KEY (domain, adsystem, seller_id, resource)
);
CREATE INDEX IF NOT EXISTS ix_ads_seller ON ads_record (adsystem, seller_id);
CREATE INDEX IF NOT EXISTS ix_ads_rel ON ads_record (adsystem, seller_id, relationship);
CREATE INDEX IF NOT EXISTS ix_ads_cid ON ads_record (cid);

-- Template fingerprints. Two domains with the same fingerprint pasted the same
-- file; their account overlap is not evidence of common control.
CREATE TABLE IF NOT EXISTS ads_fingerprint (
    domain       TEXT NOT NULL,
    resource     TEXT NOT NULL DEFAULT 'ads_txt',
    fingerprint  TEXT NOT NULL,
    record_count INTEGER DEFAULT 0,
    fetched_at   TEXT NOT NULL,
    PRIMARY KEY (domain, resource)
);
CREATE INDEX IF NOT EXISTS ix_fingerprint ON ads_fingerprint (fingerprint);

CREATE TABLE IF NOT EXISTS ads_var (
    domain     TEXT NOT NULL,
    variable   TEXT NOT NULL,
    value      TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    PRIMARY KEY (domain, variable, value)
);
CREATE INDEX IF NOT EXISTS ix_ads_var_value ON ads_var (variable, value);

CREATE TABLE IF NOT EXISTS seller (
    adsystem        TEXT NOT NULL,
    seller_id       TEXT NOT NULL,
    name            TEXT,
    domain          TEXT,
    seller_type     TEXT,
    is_confidential INTEGER DEFAULT 0,
    fetched_at      TEXT NOT NULL,
    PRIMARY KEY (adsystem, seller_id)
);
CREATE INDEX IF NOT EXISTS ix_seller_name   ON seller (name);
CREATE INDEX IF NOT EXISTS ix_seller_domain ON seller (domain);

CREATE TABLE IF NOT EXISTS analytics_id (
    domain     TEXT NOT NULL,
    scheme     TEXT NOT NULL,
    value      TEXT NOT NULL,
    first_seen TEXT,
    historical INTEGER DEFAULT 0,
    fetched_at TEXT NOT NULL,
    PRIMARY KEY (domain, scheme, value)
);
CREATE INDEX IF NOT EXISTS ix_analytics_val ON analytics_id (scheme, value);

CREATE TABLE IF NOT EXISTS corpus_meta (key TEXT PRIMARY KEY, value TEXT);
"""

_VAR = re.compile(r"^\s*(OWNERDOMAIN|MANAGERDOMAIN|INVENTORYPARTNERDOMAIN)\s*=\s*([^\s#,]+)", re.I)


@dataclass
class AdsTxtIndex:
    """Persistent corpus index. Satisfies ``SelectivityIndex``."""

    db_path: str

    def __post_init__(self) -> None:
        self.conn = sqlite3.connect(self.db_path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---- SelectivityIndex protocol ---------------------------------------- #

    def holders(self, ident: Identifier) -> int:
        """Distinct domains observed carrying this identifier value."""
        cur = self.conn.cursor()
        if ident.kind is IdKind.SELLER_ID:
            try:
                adsystem, sid = ident.value.split("/", 1)
            except ValueError:
                return 0
            cur.execute(
                "SELECT COUNT(DISTINCT domain) FROM ads_record "
                "WHERE adsystem = ? AND seller_id = ?",
                (adsystem, sid),
            )
        elif ident.kind is IdKind.ANALYTICS_ID:
            scheme, _, val = ident.value.partition(":")
            cur.execute(
                "SELECT COUNT(DISTINCT domain) FROM analytics_id "
                "WHERE scheme = ? AND value = ?", (scheme, val))
        elif ident.kind is IdKind.ORG_NAME:
            cur.execute(
                "SELECT COUNT(*) FROM seller WHERE name = ? COLLATE NOCASE", (ident.value,)
            )
        elif ident.kind is IdKind.DOMAIN:
            cur.execute(
                "SELECT (SELECT COUNT(DISTINCT domain) FROM ads_var "
                " WHERE variable = 'OWNERDOMAIN' AND value = ?) + "
                "(SELECT COUNT(*) FROM seller WHERE domain = ?)",
                (ident.value, ident.value),
            )
        else:
            return 0
        row = cur.fetchone()
        return int(row[0]) if row and row[0] else 0

    def domains_for_analytics(self, scheme: str, value: str) -> list[str]:
        """Reverse pivot: every domain observed with this publisher ID.

        Includes historical observations. A shared AdSense ID from 2019 is
        evidence of common control even if both sites have separate accounts
        today -- the scoring model decays it by age rather than discarding it.
        """
        cur = self.conn.cursor()
        cur.execute(
            "SELECT DISTINCT domain FROM analytics_id WHERE scheme = ? AND value = ? "
            "ORDER BY domain", (scheme, value))
        return [r[0] for r in cur.fetchall()]

    def holders_analytics(self, scheme: str, value: str) -> int:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT COUNT(DISTINCT domain) FROM analytics_id WHERE scheme = ? AND value = ?",
            (scheme, value))
        return int(cur.fetchone()[0] or 0)

    def account_holders(self, adsystem: str, seller_id: str,
                        relationship: str | None = None) -> int:
        """Domains declaring this account. The number that separates a real
        account from a pasted template line."""
        cur = self.conn.cursor()
        if relationship:
            cur.execute(
                "SELECT COUNT(DISTINCT domain) FROM ads_record "
                "WHERE adsystem = ? AND seller_id = ? AND relationship = ?",
                (adsystem.lower(), seller_id, relationship.upper()))
        else:
            cur.execute(
                "SELECT COUNT(DISTINCT domain) FROM ads_record "
                "WHERE adsystem = ? AND seller_id = ?",
                (adsystem.lower(), seller_id))
        return int(cur.fetchone()[0] or 0)

    def domains_sharing_fingerprint(self, fingerprint: str) -> list[str]:
        """Domains that pasted the same file. Their overlap is worthless."""
        cur = self.conn.cursor()
        cur.execute("SELECT domain FROM ads_fingerprint WHERE fingerprint = ? "
                    "ORDER BY domain", (fingerprint,))
        return [r[0] for r in cur.fetchall()]

    def domains_for_cid(self, cid: str) -> list[str]:
        """Certification authority ID (TAG-ID) -> domains. A cid ties a record
        to a certified entity rather than to a copied string."""
        cur = self.conn.cursor()
        cur.execute("SELECT DISTINCT domain FROM ads_record WHERE cid = ? AND cid != ''"
                    " ORDER BY domain", (cid,))
        return [r[0] for r in cur.fetchall()]

    def boilerplate_accounts(self, threshold: int = 150) -> list[tuple[str, str, int]]:
        """Accounts so widely duplicated they carry no signal."""
        cur = self.conn.cursor()
        cur.execute(
            "SELECT adsystem, seller_id, COUNT(DISTINCT domain) c FROM ads_record "
            "GROUP BY adsystem, seller_id HAVING c > ? ORDER BY c DESC", (threshold,))
        return cur.fetchall()

    def record_fingerprint(self, domain: str, fingerprint: str,
                           record_count: int, resource: str = "ads_txt") -> None:
        from datetime import datetime, timezone
        self.conn.execute(
            "INSERT OR REPLACE INTO ads_fingerprint VALUES (?,?,?,?,?)",
            (domain.lower(), resource, fingerprint, record_count,
             datetime.now(timezone.utc).isoformat()))
        self.conn.commit()

    def sellers_for_domain(self, domain: str) -> list[tuple[str, str]]:
        cur = self.conn.cursor()
        cur.execute("SELECT adsystem, seller_id FROM ads_record WHERE domain = ?",
                    (domain.lower(),))
        return cur.fetchall()

    def owner_domains_for(self, domain: str) -> list[str]:
        cur = self.conn.cursor()
        cur.execute("SELECT value FROM ads_var WHERE domain = ? AND variable = 'OWNERDOMAIN'",
                    (domain.lower(),))
        return [r[0] for r in cur.fetchall()]

    def record_analytics(self, domain: str, scheme: str, value: str,
                         first_seen=None, historical: bool = False) -> None:
        from datetime import datetime, timezone
        self.conn.execute(
            "INSERT OR IGNORE INTO analytics_id VALUES (?,?,?,?,?,?)",
            (domain.lower(), scheme, value,
             first_seen.isoformat() if first_seen else None,
             int(historical), datetime.now(timezone.utc).isoformat()))
        self.conn.commit()

    def universe(self) -> int:
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(DISTINCT domain) FROM ads_record")
        n = int(cur.fetchone()[0] or 0)
        return max(n, 1000)

    # ---- reverse lookups --------------------------------------------------- #

    def sites_for_seller(self, adsystem: str, seller_id: str) -> list[str]:
        """The portfolio pivot: every site declaring this seller ID."""
        cur = self.conn.cursor()
        cur.execute(
            "SELECT domain FROM ads_record WHERE adsystem = ? AND seller_id = ? "
            "ORDER BY domain",
            (adsystem.lower(), seller_id),
        )
        return [r[0] for r in cur.fetchall()]

    def sites_for_owner(self, owner_domain: str) -> list[str]:
        """Sites declaring OWNERDOMAIN = this domain -- a self-published
        portfolio map, published because DSPs penalize its absence."""
        cur = self.conn.cursor()
        cur.execute(
            "SELECT domain FROM ads_var WHERE variable = 'OWNERDOMAIN' "
            "AND value = ? ORDER BY domain",
            (owner_domain.lower(),),
        )
        return [r[0] for r in cur.fetchall()]

    def sellers_for_name(self, name: str) -> list[tuple[str, str, str]]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT adsystem, seller_id, domain FROM seller "
            "WHERE name = ? COLLATE NOCASE",
            (name,),
        )
        return cur.fetchall()

    def ad_systems(self) -> list[str]:
        cur = self.conn.cursor()
        cur.execute("SELECT DISTINCT adsystem FROM ads_record ORDER BY adsystem")
        return [r[0] for r in cur.fetchall()]

    def stats(self) -> dict:
        cur = self.conn.cursor()
        out = {}
        for label, q in (
            ("domains", "SELECT COUNT(DISTINCT domain) FROM ads_record"),
            ("ads_records", "SELECT COUNT(*) FROM ads_record"),
            ("ad_systems", "SELECT COUNT(DISTINCT adsystem) FROM ads_record"),
            ("sellers", "SELECT COUNT(*) FROM seller"),
            ("named_sellers", "SELECT COUNT(*) FROM seller WHERE name IS NOT NULL"),
            ("owner_declarations",
             "SELECT COUNT(*) FROM ads_var WHERE variable = 'OWNERDOMAIN'"),
            ("analytics_ids", "SELECT COUNT(DISTINCT scheme || value) FROM analytics_id"),
            ("boilerplate_accounts",
             "SELECT COUNT(*) FROM (SELECT adsystem, seller_id FROM ads_record "
             "GROUP BY adsystem, seller_id HAVING COUNT(DISTINCT domain) > 150)"),
            ("shared_templates",
             "SELECT COUNT(*) FROM (SELECT fingerprint FROM ads_fingerprint "
             "GROUP BY fingerprint HAVING COUNT(*) > 1)"),
            ("analytics_observations", "SELECT COUNT(*) FROM analytics_id"),
        ):
            cur.execute(q)
            out[label] = int(cur.fetchone()[0] or 0)
        return out


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #

async def crawl_ads_txt(index: AdsTxtIndex, domains: list[str], concurrency: int = 20) -> int:
    from datetime import datetime, timezone

    fetcher = Fetcher(user_agent=f"paytrace/{_VERSION} (+https://github.com/tusharkarumudi/paytrace)",
                      max_requests=len(domains) * 2 + 100)
    # Validated at the boundary that constructs the semaphore, so every caller
    # is covered -- the CLI, the library API, and anything embedding this.
    # `asyncio.Semaphore(0)` grants no permits, so the build does not run
    # slowly, it hangs with no output and no timeout.
    if concurrency < 1:
        raise ValueError(
            f"concurrency must be at least 1, got {concurrency}. A zero-permit "
            "semaphore hangs rather than disabling concurrency.")
    sem = asyncio.Semaphore(concurrency)
    now = datetime.now(timezone.utc).isoformat()
    rows_a: list[tuple] = []
    rows_v: list[tuple] = []

    async def one(domain: str) -> None:
        async with sem:
            r = await fetcher.get(f"https://{domain}/ads.txt", allow_html=True)
            if not r or r.status != 200 or not r.text:
                return
            for line in r.text.splitlines()[:5000]:
                m = _VAR.match(line)
                if m:
                    rows_v.append((domain, m.group(1).upper(), m.group(2).lower(), now))
                    continue
                body = line.split("#", 1)[0].strip()
                if not body:
                    continue
                parts = [p.strip() for p in body.split(",")]
                if len(parts) >= 3 and "." in parts[0]:
                    rel = parts[2].upper()
                    if rel in ("DIRECT", "RESELLER"):
                        cid = parts[3].strip() if len(parts) > 3 else ""
                        rows_a.append((domain, parts[0].lower(), parts[1], rel,
                                       cid, "ads_txt", now))

    await asyncio.gather(*(one(d) for d in domains))
    await fetcher.aclose()

    index.conn.executemany(
        "INSERT OR REPLACE INTO ads_record VALUES (?,?,?,?,?,?,?)", rows_a)

    # Fingerprint each file so template sharing is detectable later.
    from .adstxt import parse as _parse_ads
    by_domain: dict[str, list[tuple]] = {}
    for r in rows_a:
        by_domain.setdefault(r[0], []).append(r)
    for dom, recs in by_domain.items():
        body = "\n".join(f"{r[1]}, {r[2]}, {r[3]}" for r in recs)
        a = _parse_ads(body, dom)
        index.record_fingerprint(dom, a.template_fingerprint(), len(recs))
    index.conn.executemany(
        "INSERT OR REPLACE INTO ads_var VALUES (?,?,?,?)", rows_v)
    index.conn.commit()
    return len(rows_a)


async def crawl_sellers_json(index: AdsTxtIndex, systems: list[str] | None = None) -> int:
    from datetime import datetime, timezone

    systems = systems or index.ad_systems()
    fetcher = Fetcher(user_agent=f"paytrace/{_VERSION} (+https://github.com/tusharkarumudi/paytrace)",
                      max_requests=len(systems) + 100)
    now = datetime.now(timezone.utc).isoformat()
    rows: list[tuple] = []

    for adsystem in systems:
        data = await fetcher.get_json(f"https://{adsystem}/sellers.json")
        if not data:
            continue
        for s in data.get("sellers", []):
            sid = str(s.get("seller_id", "")).strip()
            if not sid:
                continue
            conf = int(s.get("is_confidential", 0) or 0)
            rows.append((
                adsystem, sid,
                None if conf else s.get("name"),
                None if conf else (s.get("domain") or "").lower() or None,
                str(s.get("seller_type", "")).upper() or None,
                conf, now,
            ))
    await fetcher.aclose()
    index.conn.executemany("INSERT OR REPLACE INTO seller VALUES (?,?,?,?,?,?,?)", rows)
    index.conn.commit()
    return len(rows)


def _main(argv: list[str] | None = None) -> int:
    import sys as _sys
    ap = argparse.ArgumentParser(prog="paytrace-index")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="crawl ads.txt for a domain list")
    b.add_argument("--domains", required=True, help="newline-delimited domain file")
    b.add_argument("--db", default="paytrace.sqlite")
    b.add_argument("--concurrency", type=int, default=20)

    s = sub.add_parser("sellers", help="crawl sellers.json for indexed ad systems")
    s.add_argument("--db", default="paytrace.sqlite")

    q = sub.add_parser("lookup", help="reverse lookup")
    q.add_argument("--db", default="paytrace.sqlite")
    q.add_argument("--seller", help="adsystem/seller_id")
    q.add_argument("--owner", help="owner domain")
    q.add_argument("--name", help="legal entity name")

    st = sub.add_parser("stats")
    st.add_argument("--db", default="paytrace.sqlite")

    a = ap.parse_args(argv)
    if getattr(a, "concurrency", 1) < 1:
        print(f"--concurrency must be at least 1, got {a.concurrency}. "
              "A zero-permit semaphore hangs rather than disabling "
              "concurrency.", file=_sys.stderr)
        return 2
    idx = AdsTxtIndex(a.db)

    if a.cmd == "build":
        domains = [d.strip().lower() for d in Path(a.domains).read_text().splitlines() if d.strip()]
        n = asyncio.run(crawl_ads_txt(idx, domains, a.concurrency))
        print(f"{n} ads.txt records from {len(domains)} domains")
    elif a.cmd == "sellers":
        n = asyncio.run(crawl_sellers_json(idx))
        print(f"{n} seller records")
    elif a.cmd == "lookup":
        if a.seller:
            adsystem, sid = a.seller.split("/", 1)
            for d in idx.sites_for_seller(adsystem, sid):
                print(d)
        if a.owner:
            for d in idx.sites_for_owner(a.owner):
                print(d)
        if a.name:
            for row in idx.sellers_for_name(a.name):
                print("/".join(filter(None, row)))
    elif a.cmd == "stats":
        print(json.dumps(idx.stats(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
