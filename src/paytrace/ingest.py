"""Ingest from SpiderFoot and OpenCTI.

Positioning, stated plainly: this toolkit should not try to out-collect
SpiderFoot. It has a decade of module development and 200+ data sources. What it
does not do is decide what its correlations are *worth* — every edge is uniform,
and the connected component is left to the analyst to interpret.

So consume it. SpiderFoot and OpenCTI supply breadth; this supplies the
calibrated inference step. That is a much stronger position than another
collector framework, and roughly a tenth the maintenance.

Both adapters translate foreign records into ``Claim`` objects with correlation
groups assigned according to what actually constitutes one observation in the
source system — which is the part that cannot be automated generically and is
where the value of the adapter lies.
"""

from __future__ import annotations

import contextlib
import csv
import json
import sqlite3
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from attribution_graph import Claim, Identifier, IdKind, Predicate, Reliability

# --------------------------------------------------------------------------- #
# SpiderFoot
# --------------------------------------------------------------------------- #

#: SpiderFoot event types -> our identifier kinds. Types not listed are ignored
#: rather than guessed at; a wrong kind produces a wrong selectivity lookup and
#: therefore a wrong score.
SF_EVENT_KIND: dict[str, IdKind] = {
    "DOMAIN_NAME": IdKind.DOMAIN,
    "INTERNET_NAME": IdKind.DOMAIN,
    "AFFILIATE_DOMAIN_NAME": IdKind.DOMAIN,
    "CO_HOSTED_SITE": IdKind.DOMAIN,
    "SIMILARDOMAIN": IdKind.DOMAIN,
    "IP_ADDRESS": IdKind.IP,
    "IPV6_ADDRESS": IdKind.IP,
    "BGP_AS_OWNER": IdKind.ASN,
    "BGP_AS_MEMBER": IdKind.ASN,
    "EMAILADDR": IdKind.EMAIL,
    "EMAILADDR_GENERIC": IdKind.EMAIL,
    "AFFILIATE_EMAILADDR": IdKind.EMAIL,
    "USERNAME": IdKind.HANDLE,
    "ACCOUNT_EXTERNAL_OWNED": IdKind.HANDLE,
    "HUMAN_NAME": IdKind.PERSON_NAME,
    "COMPANY_NAME": IdKind.ORG_NAME,
    "PHONE_NUMBER": IdKind.PHONE,
    "PHYSICAL_ADDRESS": IdKind.POSTAL_ADDRESS,
    "SSL_CERTIFICATE_ISSUED": IdKind.CERT_SHA256,
    "WEB_ANALYTICS_ID": IdKind.ANALYTICS_ID,
    "PGP_KEY": IdKind.PGP_FPR,
    "SIMILAR_ACCOUNT_EXTERNAL": IdKind.HANDLE,
}

#: Event types whose relationship to the source is co-hosting or shared
#: infrastructure rather than ownership.
SF_INFRA_EVENTS = {
    "CO_HOSTED_SITE", "IP_ADDRESS", "IPV6_ADDRESS", "BGP_AS_OWNER", "BGP_AS_MEMBER",
}

#: SpiderFoot modules whose output is inference rather than observation, or is
#: known noisy. Downgraded rather than dropped.
SF_WEAK_MODULES = {
    "sfp_similar", "sfp_similardomain", "sfp_namegen", "sfp_crossref",
    "sfp_company", "sfp_names",
}


def _sf_predicate(event_type: str) -> Predicate:
    if event_type in SF_INFRA_EVENTS:
        return Predicate.CO_HOSTED
    if event_type == "WEB_ANALYTICS_ID":
        return Predicate.SHARES_ANALYTICS_ID
    if event_type in ("EMAILADDR", "EMAILADDR_GENERIC", "AFFILIATE_EMAILADDR"):
        return Predicate.REGISTRANT
    if event_type in ("USERNAME", "ACCOUNT_EXTERNAL_OWNED", "SIMILAR_ACCOUNT_EXTERNAL"):
        return Predicate.PROFILE_BINDING
    if event_type in ("HUMAN_NAME", "COMPANY_NAME"):
        return Predicate.REGISTRANT
    if event_type == "SSL_CERTIFICATE_ISSUED":
        return Predicate.SHARES_CERT
    return Predicate.PROFILE_BINDING


def _sf_reliability(module: str, event_type: str) -> Reliability:
    if module in SF_WEAK_MODULES or event_type.startswith("SIMILAR"):
        return Reliability.WEAK
    if event_type in SF_INFRA_EVENTS:
        return Reliability.MODERATE
    if event_type in ("WEB_ANALYTICS_ID", "PGP_KEY", "SSL_CERTIFICATE_ISSUED"):
        return Reliability.STRONG
    return Reliability.MODERATE


def _sf_claim(
    source_value: str, source_type: str, event_type: str, data: str,
    module: str, when: datetime | None, scan_id: str,
) -> Claim | None:
    obj_kind = SF_EVENT_KIND.get(event_type)
    subj_kind = SF_EVENT_KIND.get(source_type, IdKind.DOMAIN)
    if not obj_kind or not data.strip() or not source_value.strip():
        return None

    return Claim(
        subject=Identifier(subj_kind, source_value.strip()),
        predicate=_sf_predicate(event_type),
        object=Identifier(obj_kind, data.strip()),
        collector=f"spiderfoot:{module}",
        source_url=f"spiderfoot://scan/{scan_id}",
        reliability=_sf_reliability(module, event_type),
        observed_at=when,
        # One SpiderFoot module run against one source entity is one
        # observation. A module emitting 200 events has queried one API once.
        correlation_group=f"spiderfoot|{scan_id}|{module}|{source_value.strip()}",
        raw={"sf_event_type": event_type, "sf_module": module, "scan_id": scan_id},
    )


def from_spiderfoot_csv(path: str | Path) -> list[Claim]:
    """Ingest a SpiderFoot CSV export.

    Expected columns (SpiderFoot's default export): Updated, Type, Module,
    Source, F/P, Data.
    """
    claims: list[Claim] = []
    p = Path(path)
    scan_id = p.stem
    with p.open(newline="", encoding="utf-8", errors="ignore") as fh:
        for row in csv.DictReader(fh):
            if str(row.get("F/P", "")).strip() in ("1", "True", "true"):
                continue                      # analyst marked it a false positive
            c = _sf_claim(
                source_value=row.get("Source", ""),
                source_type=row.get("Source Type", "DOMAIN_NAME"),
                event_type=row.get("Type", ""),
                data=row.get("Data", ""),
                module=row.get("Module", "unknown"),
                when=_parse(row.get("Updated")),
                scan_id=scan_id,
            )
            if c:
                claims.append(c)
    return claims


def from_spiderfoot_db(path: str | Path, scan_id: str | None = None) -> list[Claim]:
    """Ingest directly from SpiderFoot's SQLite store.

    Preferred over CSV: it preserves event types on both sides of the relation,
    which the CSV export flattens.
    """
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    q = """
        SELECT r.scan_instance_id AS scan_id, r.type AS event_type,
               r.data AS data, r.module AS module, r.generated AS generated,
               r.false_positive AS fp,
               s.data AS source_data, s.type AS source_type
        FROM tbl_scan_results r
        LEFT JOIN tbl_scan_results s ON r.source_event_hash = s.hash
        WHERE r.false_positive = 0
    """
    params: tuple = ()
    if scan_id:
        q += " AND r.scan_instance_id = ?"
        params = (scan_id,)

    claims: list[Claim] = []
    try:
        for row in conn.execute(q, params):
            when = None
            if row["generated"]:
                with contextlib.suppress(ValueError, OSError):
                    when = datetime.fromtimestamp(int(row["generated"]), tz=timezone.utc)
            c = _sf_claim(
                source_value=row["source_data"] or "",
                source_type=row["source_type"] or "DOMAIN_NAME",
                event_type=row["event_type"] or "",
                data=row["data"] or "",
                module=row["module"] or "unknown",
                when=when,
                scan_id=row["scan_id"] or "unknown",
            )
            if c:
                claims.append(c)
    finally:
        conn.close()
    return claims


# --------------------------------------------------------------------------- #
# OpenCTI
# --------------------------------------------------------------------------- #

#: STIX / OpenCTI observable types -> identifier kinds.
STIX_KIND: dict[str, IdKind] = {
    "Domain-Name": IdKind.DOMAIN,
    "Hostname": IdKind.DOMAIN,
    "IPv4-Addr": IdKind.IP,
    "IPv6-Addr": IdKind.IP,
    "Autonomous-System": IdKind.ASN,
    "Email-Addr": IdKind.EMAIL,
    "User-Account": IdKind.HANDLE,
    "Url": IdKind.URL,
    "X509-Certificate": IdKind.CERT_SHA256,
    "Organization": IdKind.ORG_NAME,
    "Identity": IdKind.ORG_NAME,
    "Individual": IdKind.PERSON_NAME,
    "Phone-Number": IdKind.PHONE,
}

STIX_PREDICATE: dict[str, Predicate] = {
    "related-to": Predicate.CO_HOSTED,
    "resolves-to": Predicate.CO_HOSTED,
    "belongs-to": Predicate.OPERATES,
    "attributed-to": Predicate.OPERATES,
    "owns": Predicate.OPERATES,
    "part-of": Predicate.PARENT_OF,
    "located-at": Predicate.REGISTERED_ADDRESS,
    "employed-by": Predicate.EMPLOYED_BY,
}

#: OpenCTI confidence (0-100) mapped onto reliability. OpenCTI's confidence is
#: analyst-entered rather than computed, so it caps at STRONG -- an analyst
#: typing 100 is not the same as a registry assertion.
def _stix_reliability(confidence: int | None) -> Reliability:
    c = confidence if confidence is not None else 50
    if c >= 85:
        return Reliability.STRONG
    if c >= 60:
        return Reliability.MODERATE
    if c >= 30:
        return Reliability.WEAK
    return Reliability.UNCERTAIN


def from_opencti_bundle(path_or_obj: str | Path | dict) -> list[Claim]:
    """Ingest a STIX 2.1 bundle exported from OpenCTI.

    Resolves SRO relationships against the observables in the same bundle.
    Relationships referencing objects outside the bundle are skipped rather than
    guessed at.
    """
    if isinstance(path_or_obj, dict):
        bundle = path_or_obj
    else:
        bundle = json.loads(Path(path_or_obj).read_text())

    objects: dict[str, dict[str, Any]] = {
        o["id"]: o for o in bundle.get("objects", []) if "id" in o
    }

    def ident_for(sid: str) -> Identifier | None:
        o = objects.get(sid)
        if not o:
            return None
        kind = STIX_KIND.get(o.get("type", ""))
        if not kind:
            # Identity objects carry their real class in identity_class
            if o.get("type") == "identity":
                kind = (IdKind.PERSON_NAME if o.get("identity_class") == "individual"
                        else IdKind.ORG_NAME)
            else:
                return None
        value = (o.get("value") or o.get("name") or o.get("user_id")
                 or o.get("account_login") or o.get("number"))
        return Identifier(kind, str(value)) if value else None

    claims: list[Claim] = []
    for o in bundle.get("objects", []):
        if o.get("type") != "relationship":
            continue
        subj = ident_for(o.get("source_ref", ""))
        obj = ident_for(o.get("target_ref", ""))
        if not (subj and obj):
            continue
        rtype = o.get("relationship_type", "related-to")
        claims.append(Claim(
            subject=subj,
            predicate=STIX_PREDICATE.get(rtype, Predicate.CO_HOSTED),
            object=obj,
            collector="opencti",
            source_url=o.get("x_opencti_id") or o.get("id", "opencti://bundle"),
            reliability=_stix_reliability(o.get("confidence")),
            observed_at=_parse(o.get("start_time") or o.get("created")),
            # One relationship object is one assertion. Where OpenCTI records
            # the originating report, group by it instead -- a report asserting
            # forty relationships is one source, not forty.
            correlation_group=(
                f"opencti|{o['created_by_ref']}" if o.get("created_by_ref")
                else f"opencti|{o.get('id', 'rel')}"
            ),
            raw={"stix_relationship": rtype,
                 "opencti_confidence": o.get("confidence"),
                 "stix_id": o.get("id")},
        ))
    return claims


# --------------------------------------------------------------------------- #

def _parse(v: Any) -> datetime | None:
    if not v:
        return None
    s = str(v).strip()
    for f in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S",
              "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:26], f).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def summarize(claims: Iterable[Claim]) -> str:
    claims = list(claims)
    by_collector: dict[str, int] = {}
    groups: set[str] = set()
    for c in claims:
        by_collector[c.collector] = by_collector.get(c.collector, 0) + 1
        groups.add(c.correlation_group)
    L = [f"{len(claims)} claims from {len(by_collector)} module(s), "
         f"{len(groups)} correlation groups", ""]
    for k, n in sorted(by_collector.items(), key=lambda kv: -kv[1])[:20]:
        L.append(f"  {n:6}  {k}")
    if claims and len(groups) < len(claims) / 4:
        L += ["", "Note: claims heavily outnumber correlation groups, which is "
                  "expected — a module that emitted hundreds of events queried "
                  "one source once."]
    return "\n".join(L)
