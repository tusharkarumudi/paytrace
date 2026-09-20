"""Ingest from Robin (AI-powered dark web OSINT).

https://github.com/apurvsinghgautam/robin — MIT licensed.

Robin searches dark web engines over Tor, scrapes results, and uses an LLM to
refine queries and summarise findings. It is a strong collector and a poor
evidence source, and the distinction matters for how it is wired in.

## Three things about Robin's data that shape this adapter

**It discards the bytes.** ``scrape.py`` caps extracted text at 2,000 characters,
strips scripts and styles, and normalises whitespace. Sensible for an LLM
context window and fatal for a chain of custody: you cannot hash-preserve what
was never kept. Text arriving through this adapter is therefore recorded as a
*derived* artifact, not a capture, and the evidence manifest says so.

**.onion content is uniquely unrecoverable.** There is no Wayback for hidden
services, no Certificate Transparency, and forums vanish without notice. Every
other source in this toolkit can be re-fetched or archived; this one cannot. That
makes capture-at-time more important here than anywhere else, and it is the
argument for adding raw preservation upstream rather than working around its
absence.

**One search is one observation.** A Robin query returns N results from one
engine. Those N results are one query against one index, not N independent
confirmations — and an LLM summary presenting them as corroborating findings is
precisely the correlated-evidence failure the scoring model exists to prevent.
Correlation groups here are keyed on ``(engine, query)``, never per result.

## Reliability ceiling on LLM output

Anything the LLM concluded — that two handles are one actor, that a vendor and a
forum account are connected — is inference over text, not observation. It enters
at ``Reliability.UNCERTAIN`` and is marked ``llm_derived`` in ``raw``.

This is not a judgement about model quality. It is that an LLM assertion and a
registry assertion are different kinds of thing, and a model that cannot tell
them apart will happily let a summarisation carry an attribution. Observations
extracted by regex from Robin's scraped text — a handle, a PGP fingerprint, a
wallet — are treated as observations, because those are things that were on the
page rather than things a model thought about the page.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from attribution_graph import Claim, Identifier, IdKind, Predicate, Reliability

# --------------------------------------------------------------------------- #
# Extraction patterns
# --------------------------------------------------------------------------- #
#
# Ordered by selectivity. Only patterns whose matches are durable identifiers
# are included -- extracting every capitalised word from forum text produces
# noise that the scoring model then has to work to discount.

PATTERNS: dict[str, tuple[re.Pattern, IdKind, Reliability]] = {
    "pgp_fingerprint": (
        re.compile(r"\b([0-9A-Fa-f]{40})\b"), IdKind.PGP_FPR, Reliability.STRONG),
    "pgp_keyid": (
        re.compile(r"\b(?:0x)?([0-9A-Fa-f]{16})\b"), IdKind.PGP_FPR, Reliability.MODERATE),
    "onion_v3": (
        re.compile(r"\b([a-z2-7]{56}\.onion)\b"), IdKind.DOMAIN, Reliability.AUTHORITATIVE),
    "email": (
        re.compile(r"\b([\w.+\-]{1,64}@[\w\-]{1,63}(?:\.[\w\-]{1,63}){1,4})\b"),
        IdKind.EMAIL, Reliability.STRONG),
    "btc": (
        re.compile(r"\b((?:bc1[a-z0-9]{25,62})|(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}))\b"),
        IdKind.URL, Reliability.STRONG),
    "xmr": (
        re.compile(r"\b(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b"), IdKind.URL, Reliability.STRONG),
    "eth": (
        re.compile(r"\b(0x[a-fA-F0-9]{40})\b"), IdKind.URL, Reliability.STRONG),
    "session_id": (
        re.compile(r"\b(05[0-9a-f]{64})\b"), IdKind.HANDLE, Reliability.STRONG),
    "tox_id": (
        re.compile(r"\b([0-9A-F]{76})\b"), IdKind.HANDLE, Reliability.STRONG),
    "telegram": (
        re.compile(r"(?:t\.me/|telegram:\s*@?|@)([A-Za-z][A-Za-z0-9_]{4,31})\b"),
        IdKind.HANDLE, Reliability.WEAK),
    "jabber": (
        re.compile(r"\b(?:jabber|xmpp)[:\s]+([\w.\-]{1,64}@[\w\-]{1,63}"
                   r"(?:\.[\w\-]{1,63}){1,4})\b", re.I),
        IdKind.HANDLE, Reliability.MODERATE),
}

#: Handle-like tokens in forum text. Deliberately conservative: a bare word is
#: not a handle, and treating it as one floods the graph with noise.
HANDLE_CONTEXT = re.compile(
    r"(?:user|username|vendor|seller|author|posted by|handle|nick|alias|account)"
    r"[:\s]+@?([A-Za-z][A-Za-z0-9_.\-]{3,31})\b",
    re.I,
)

#: Words that survive the pattern above but never denote a person.
HANDLE_STOPWORDS = frozenset({
    "anonymous", "admin", "administrator", "moderator", "unknown", "deleted",
    "guest", "member", "staff", "system", "support", "verified", "trusted",
    "name", "here", "above", "below", "this", "that", "none", "null",
})

#: Structural false positives from the wide hex patterns.
HEX_FALSE_POSITIVES = re.compile(r"^(0+|f+|F+|[0-9]+|deadbeef.*)$")


def _clean_matches(kind: str, values: Iterable[str]) -> list[str]:
    out: list[str] = []
    for v in values:
        v = v.strip()
        if not v:
            continue
        if kind in ("pgp_fingerprint", "pgp_keyid", "tox_id") and \
                HEX_FALSE_POSITIVES.match(v):
            continue
        if kind == "telegram" and v.lower() in HANDLE_STOPWORDS:
            continue
        out.append(v)
    return list(dict.fromkeys(out))


# --------------------------------------------------------------------------- #
# Robin result shapes
# --------------------------------------------------------------------------- #

def _iter_results(data: Any) -> Iterable[tuple[str, str, str, str]]:
    """Yield ``(url, text, engine, query)`` from whatever Robin handed us.

    Robin's saved-investigation schema is not a stable public contract, so this
    accepts the shapes it currently produces and degrades rather than raising.
    Confirm against your Robin version before relying on the output.
    """
    # scrape_multiple() output: {url: text}
    if isinstance(data, dict) and all(isinstance(v, str) for v in data.values()):
        for url, text in data.items():
            yield url, text, "robin", ""
        return

    if isinstance(data, dict):
        query = str(data.get("query") or data.get("original_query") or "")
        engine = str(data.get("engine") or data.get("search_engine") or "robin")

        results = (data.get("results") or data.get("scraped")
                   or data.get("sources") or data.get("findings") or [])
        if isinstance(results, dict):
            for url, text in results.items():
                yield str(url), str(text), engine, query
            return
        for r in results if isinstance(results, list) else []:
            if isinstance(r, dict):
                yield (str(r.get("link") or r.get("url") or ""),
                       str(r.get("content") or r.get("text") or r.get("title") or ""),
                       str(r.get("engine") or engine), query)
        return

    if isinstance(data, list):
        for item in data:
            yield from _iter_results(item)


# --------------------------------------------------------------------------- #
# Ingest
# --------------------------------------------------------------------------- #

def from_robin(
    path_or_obj: str | Path | dict | list,
    *,
    observed_at: datetime | None = None,
    include_llm_summary: bool = True,
) -> list[Claim]:
    """Convert a Robin investigation into scored claims."""
    if isinstance(path_or_obj, (str, Path)):
        data = json.loads(Path(path_or_obj).read_text())
    else:
        data = path_or_obj

    when = observed_at or datetime.now(timezone.utc)
    claims: list[Claim] = []

    for url, text, engine, query in _iter_results(data):
        if not url:
            continue
        source = Identifier(IdKind.URL, url)

        # One group per (engine, query, url). All identifiers on one page came
        # from one retrieval of one page.
        group = f"robin|{engine}|{query or 'unspecified'}|{url}"

        for kind, (pattern, id_kind, reliability) in PATTERNS.items():
            for value in _clean_matches(kind, pattern.findall(text or "")):
                claims.append(Claim(
                    subject=source,
                    predicate=Predicate.PROFILE_BINDING,
                    object=Identifier(id_kind, value),
                    collector=f"robin:{kind}",
                    source_url=url,
                    reliability=reliability,
                    observed_at=when,
                    correlation_group=group,
                    raw={"extraction": kind, "engine": engine, "query": query,
                         "onion": ".onion" in url,
                         "text_is_derived": True,
                         "note": "extracted from Robin's truncated scrape; "
                                 "raw response body was not preserved"},
                ))

        for handle in _clean_matches("handle", HANDLE_CONTEXT.findall(text or "")):
            if handle.lower() in HANDLE_STOPWORDS or len(handle) < 4:
                continue
            claims.append(Claim(
                subject=source,
                predicate=Predicate.PROFILE_BINDING,
                object=Identifier(IdKind.HANDLE, f"darkweb:{handle}"),
                collector="robin:handle",
                source_url=url,
                reliability=Reliability.WEAK,
                observed_at=when,
                correlation_group=group,
                raw={"extraction": "handle_context", "engine": engine,
                     "query": query, "text_is_derived": True},
            ))

    if include_llm_summary and isinstance(data, dict):
        claims.extend(_llm_claims(data, when))

    return claims


def _llm_claims(data: dict, when: datetime) -> list[Claim]:
    """Claims from Robin's LLM summary, capped at UNCERTAIN.

    An LLM concluding two handles are one actor is inference over text. It can
    corroborate a link that has independent support; it must not create one.
    """
    summary = (data.get("summary") or data.get("investigation_summary")
               or data.get("analysis") or "")
    if not isinstance(summary, str) or len(summary) < 40:
        return []

    query = str(data.get("query") or "")
    claims: list[Claim] = []
    subject = Identifier(IdKind.URL, f"robin-investigation:{query or 'unspecified'}")

    for kind, (pattern, id_kind, _) in PATTERNS.items():
        for value in _clean_matches(kind, pattern.findall(summary)):
            claims.append(Claim(
                subject=subject,
                predicate=Predicate.PROFILE_BINDING,
                object=Identifier(id_kind, value),
                collector="robin:llm_summary",
                source_url="robin://summary",
                reliability=Reliability.UNCERTAIN,
                observed_at=when,
                # The entire summary is one LLM generation: one group, always.
                correlation_group=f"robin_llm|{query or 'unspecified'}",
                raw={"llm_derived": True, "extraction": kind,
                     "note": "asserted by a language model summarising scraped "
                             "text, not observed directly; corroborative only"},
            ))
    return claims


# --------------------------------------------------------------------------- #
# Handle export
# --------------------------------------------------------------------------- #

def to_handle_observations(
    claims: Iterable[Claim], case_ref: str = ""
) -> list[dict[str, Any]]:
    """Rows for ``handle-correlation``, keyed on the handles Robin surfaced.

    Durable identifiers found on the same page as a handle become that handle's
    ``link_*`` fields — which is what lets a shared PGP key lift two forum
    accounts above the correlation-point floor. Without those links, handle
    similarity alone stays INSUFFICIENT no matter how many forums it appears on.
    """
    by_page: dict[str, dict[str, Any]] = {}

    for c in claims:
        if not isinstance(c.object, Identifier):
            continue
        page = c.source_url
        entry = by_page.setdefault(page, {"handles": [], "links": {}})

        if c.object.kind is IdKind.HANDLE:
            entry["handles"].append(c.object.value.split(":", 1)[-1])
        elif c.object.kind is IdKind.PGP_FPR:
            entry["links"].setdefault("pgp", c.object.value)
        elif c.object.kind is IdKind.EMAIL:
            entry["links"].setdefault("email", c.object.value)
        elif c.object.kind is IdKind.DOMAIN:
            entry["links"].setdefault("domain", c.object.value)

    rows: list[dict[str, Any]] = []
    for page, entry in by_page.items():
        for handle in dict.fromkeys(entry["handles"]):
            row = {
                "handle": handle,
                "platform": "darkweb",
                "source_url": page,
                "case_ref": case_ref,
            }
            for k, v in entry["links"].items():
                row[f"link_{k}"] = v
            rows.append(row)
    return rows


def summarize(claims: Iterable[Claim]) -> str:
    claims = list(claims)
    if not claims:
        return "no claims extracted"

    by_collector: dict[str, int] = {}
    groups: set[str] = set()
    onion = 0
    llm = 0
    for c in claims:
        by_collector[c.collector] = by_collector.get(c.collector, 0) + 1
        groups.add(c.correlation_group)
        onion += bool(c.raw.get("onion"))
        llm += bool(c.raw.get("llm_derived"))

    L = [f"{len(claims)} claims, {len(groups)} correlation group(s)",
         f"{onion} from .onion sources, {llm} LLM-derived (capped at UNCERTAIN)", ""]
    for k, n in sorted(by_collector.items(), key=lambda kv: -kv[1]):
        L.append(f"  {n:5}  {k}")
    L += ["",
          "Text arrived truncated and derived; raw response bodies were not "
          "preserved by Robin. These claims are leads, and .onion sources cannot "
          "be re-fetched later to verify them."]
    return "\n".join(L)
