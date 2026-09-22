"""Tool layer: toolkit functions exposed to an agent.

Every tool returns a ``ToolResult`` that separates three things the agent must
never conflate:

    structured   parsed, spec-defined fields. Trustworthy as *data*.
    freetext     operator-controlled prose. Untrusted, always.
    provenance   who published this, and are they the investigation's subject?

The separation exists because of a property specific to attribution work: **the
data you collect is authored by the entity you are investigating.** An
``ads.txt`` file, a ``sellers.json`` record, an imprint page — the subject wrote
all of them. In most agent settings untrusted tool output is an edge case. Here
it is the normal case, and an agent that treats retrieved text as instructions is
taking direction from its target.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from attribution_graph import Claim, Identifier, IdKind, Predicate, Reliability


class SourceUnavailable(RuntimeError):
    """The source could not be reached or refused. An ordinary investigative
    outcome, not a defect."""


class ParseError(RuntimeError):
    """The source responded with something we could not interpret."""


#: Exceptions that represent the world being uncooperative rather than the code
#: being wrong. Anything outside this set is our defect and is re-raised in
#: development, because a TypeError that reports as "tool failed" makes a
#: production bug indistinguishable from a source being down.
EXPECTED_FAILURES: tuple[type[Exception], ...] = (
    SourceUnavailable, ParseError, TimeoutError, ConnectionError, OSError,
    ValueError, KeyError,
)


class Trust(StrEnum):
    """Who authored the bytes, not how reliable the format is."""

    REGISTRY = "registry"          # statutory source; the subject cannot edit it
    THIRD_PARTY = "third_party"    # CT logs, passive DNS, archive
    SUBJECT = "subject"            # written by the entity under investigation
    DERIVED = "derived"            # produced by another model


@dataclass
class ToolResult:
    tool: str
    ok: bool
    structured: dict[str, Any] = field(default_factory=dict)
    freetext: dict[str, str] = field(default_factory=dict)
    trust: Trust = Trust.SUBJECT
    source_url: str = ""
    error: str = ""
    claims: list[Claim] = field(default_factory=list)
    retrieved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    notes: list[str] = field(default_factory=list)

    def agent_view(self, include_freetext: bool = False) -> str:
        """What the agent's context actually receives.

        ``freetext`` is withheld by default. It is the field an operator
        controls, and there is no investigative question it answers that the
        structured fields do not answer better.
        """
        payload: dict[str, Any] = {
            "tool": self.tool,
            "ok": self.ok,
            "source": self.source_url,
            "trust": self.trust.value,
            "data": self.structured,
        }
        if self.error:
            payload["error"] = self.error
        if include_freetext and self.freetext:
            payload["operator_supplied_freetext"] = self.freetext
        return json.dumps(payload, indent=2, default=str)


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, str]
    trust: Trust
    fn: Callable[..., ToolResult]

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    k: {"type": "string", "description": v}
                    for k, v in self.parameters.items()
                },
                "required": list(self.parameters),
            },
        }


class Toolbox:
    """Tools bound to a fetcher. Swap the fetcher for fixtures to run offline."""

    def __init__(self, fetcher, index=None, strict: bool = False) -> None:
        self.fetcher = fetcher
        self.index = index
        #: Re-raise unexpected exceptions instead of recording them as tool
        #: failures. Default off so a live run survives; on in development and
        #: in CI, where a masked defect is worse than a stopped run.
        self.strict = strict
        self.calls: list[tuple[str, dict, ToolResult]] = []
        self._tools: dict[str, Tool] = {}
        self._register_all()

    # -- registration ------------------------------------------------------- #

    def _register_all(self) -> None:
        self.register("fetch_ads_txt",
                      "Fetch a domain's ads.txt. Returns declared ad-system "
                      "seller IDs and any OWNERDOMAIN/MANAGERDOMAIN variables.",
                      {"domain": "domain to fetch, e.g. example.com"},
                      Trust.SUBJECT, self._ads_txt)

        self.register("fetch_sellers_json",
                      "Fetch an ad system's sellers.json and return the record "
                      "for one seller_id. Confirms or contradicts an ads.txt "
                      "declaration.",
                      {"adsystem": "ad system domain", "seller_id": "seller id"},
                      Trust.SUBJECT, self._sellers_json)

        self.register("extract_analytics_ids",
                      "Extract publisher-account identifiers (AdSense, GA4, GTM, "
                      "Pixel) from a domain's live page source.",
                      {"domain": "domain to inspect"},
                      Trust.SUBJECT, self._analytics)

        self.register("reverse_lookup_identifier",
                      "Find every other domain in the corpus carrying an "
                      "identifier. Reports holder count so low-selectivity "
                      "identifiers can be discarded.",
                      {"identifier": "e.g. adsense:1234567890123456"},
                      Trust.THIRD_PARTY, self._reverse)

        self.register("lookup_gleif",
                      "Look up a legal entity in the GLEIF LEI index. Returns "
                      "LEI, jurisdiction, registered address and national "
                      "company number.",
                      {"org_name": "legal entity name"},
                      Trust.REGISTRY, self._gleif)

        self.register("lookup_companies_house",
                      "Look up UK company officers and persons with significant "
                      "control.",
                      {"company_number": "UK company number"},
                      Trust.REGISTRY, self._companies_house)

        self.register("lookup_rdap",
                      "Fetch RDAP registration data for a domain.",
                      {"domain": "domain to look up"},
                      Trust.REGISTRY, self._rdap)

    def register(self, name, description, parameters, trust, fn) -> None:
        self._tools[name] = Tool(name, description, parameters, trust, fn)

    def schemas(self) -> list[dict[str, Any]]:
        return [t.schema() for t in self._tools.values()]

    def names(self) -> list[str]:
        return list(self._tools)

    def call(self, name: str, **kwargs) -> ToolResult:
        tool = self._tools.get(name)
        if not tool:
            r = ToolResult(tool=name, ok=False, error=f"no such tool: {name}")
        else:
            try:
                r = tool.fn(**kwargs)
            except EXPECTED_FAILURES as e:
                # The world was uncooperative. Record it and continue.
                r = ToolResult(tool=name, ok=False, error=repr(e), trust=tool.trust)
            except Exception as e:
                # Our defect. Surface it loudly unless the caller has explicitly
                # asked for resilience over diagnosis.
                if self.strict:
                    raise
                r = ToolResult(
                    tool=name, ok=False, error=f"INTERNAL DEFECT: {e!r}",
                    trust=tool.trust,
                    notes=["this is a bug in the toolkit, not a source failure; "
                           "run with strict=True to raise it"])
        self.calls.append((name, kwargs, r))
        return r

    # -- implementations ----------------------------------------------------- #

    def _ads_txt(self, domain: str) -> ToolResult:
        url = f"https://{domain}/ads.txt"
        body = self.fetcher.get_text(url)
        if body is None:
            return ToolResult("fetch_ads_txt", False, error="not retrievable",
                              trust=Trust.SUBJECT, source_url=url)

        sellers, variables, comments = [], {}, []
        for line in body.splitlines():
            if "#" in line:
                tail = line.split("#", 1)[1].strip()
                if tail:
                    comments.append(tail)
            payload = line.split("#", 1)[0].strip()
            if not payload:
                continue
            if "=" in payload and "," not in payload:
                k, _, v = payload.partition("=")
                variables[k.strip().upper()] = v.strip().lower()
                continue
            parts = [p.strip() for p in payload.split(",")]
            if len(parts) >= 3 and "." in parts[0]:
                sellers.append({"adsystem": parts[0].lower(),
                                "seller_id": parts[1],
                                "relationship": parts[2].upper()})

        claims = [
            Claim(subject=Identifier(IdKind.DOMAIN, domain),
                  predicate=Predicate.SELLER_OF,
                  object=Identifier(IdKind.SELLER_ID,
                                    f"{s['adsystem']}/{s['seller_id']}"),
                  collector="agent:fetch_ads_txt", source_url=url,
                  reliability=Reliability.STRONG,
                  correlation_group=f"ads_txt|{domain}")
            for s in sellers
        ]
        return ToolResult(
            "fetch_ads_txt", True,
            structured={"domain": domain, "sellers": sellers, "variables": variables},
            freetext={"comments": " | ".join(comments)} if comments else {},
            trust=Trust.SUBJECT, source_url=url, claims=claims)

    def _sellers_json(self, adsystem: str, seller_id: str) -> ToolResult:
        from ..sellersjson import (
            SellerNameKind,
            candidate_urls,
            classify_seller_name,
            find_seller_in_text,
        )

        # Not always the domain root: Google publishes at
        # storage.googleapis.com, and a root-only fetch silently returns
        # nothing for the largest ad system there is.
        rec, url = None, ""
        for candidate in candidate_urls(adsystem):
            body = self.fetcher.get_text(candidate)
            if body is None:
                continue
            url = candidate
            rec = find_seller_in_text(body, adsystem, seller_id, candidate)
            if rec:
                break
        if rec is None:
            return ToolResult("fetch_sellers_json", True,
                              structured={"found": False, "seller_id": seller_id},
                              trust=Trust.SUBJECT, source_url=url,
                              notes=["seller_id not located in sellers.json"])

        for s in [{"seller_id": rec.seller_id, "name": rec.name,
                   "domain": rec.domain, "seller_type": rec.seller_type,
                   "is_confidential": int(rec.is_confidential),
                   **({"comment": rec.comment} if rec.comment else {}),
                   **rec.extra}]:

            # Spec-defined structural fields only. Everything else -- comment,
            # ext, and any field a publisher invented -- is operator prose and
            # is routed to freetext.
            structural = {k: s.get(k) for k in
                          ("seller_id", "name", "domain", "seller_type",
                           "is_confidential") if k in s}
            free = {k: str(v) for k, v in s.items()
                    if k not in structural and isinstance(v, (str, int, float))}

            claims = []
            if s.get("name") and not int(s.get("is_confidential", 0) or 0):
                claims.append(Claim(
                    subject=Identifier(IdKind.SELLER_ID, f"{adsystem}/{seller_id}"),
                    predicate=Predicate.LEGAL_NAME,
                    # Delegates to the canonical classifier. This previously
                    # hard-coded ORG_NAME while sellersjson.classify_seller_name
                    # existed, so the agent path typed individual publishers as
                    # organisations and routed them to corporate registries that
                    # hold no record. Agent tools must wrap domain services, not
                    # reimplement them.
                    object=Identifier(
                        IdKind.PERSON_NAME
                        if classify_seller_name(s["name"]) is
                        SellerNameKind.NATURAL_PERSON
                        else IdKind.ORG_NAME, s["name"]),
                    collector="agent:fetch_sellers_json", source_url=url,
                    reliability=Reliability.STRONG,
                    correlation_group=f"sellers_json|{adsystem}|{seller_id}"))

            return ToolResult("fetch_sellers_json", True, structured=structural,
                              freetext=free, trust=Trust.SUBJECT,
                              source_url=url, claims=claims)

        return ToolResult("fetch_sellers_json", True,
                          structured={"found": False, "seller_id": seller_id},
                          trust=Trust.SUBJECT, source_url=url,
                          notes=["seller_id absent from sellers.json"])

    def _analytics(self, domain: str) -> ToolResult:
        from ..collectors.analytics import extract_ids
        url = f"https://{domain}/"
        body = self.fetcher.get_text(url)
        if body is None:
            return ToolResult("extract_analytics_ids", False, error="not retrievable",
                              trust=Trust.SUBJECT, source_url=url)
        ids = [{"scheme": k, "value": v} for k, v, _ in extract_ids(body)]
        claims = [
            Claim(subject=Identifier(IdKind.DOMAIN, domain),
                  predicate=Predicate.SHARES_ANALYTICS_ID,
                  object=Identifier(IdKind.ANALYTICS_ID, f"{i['scheme']}:{i['value']}"),
                  collector="agent:extract_analytics_ids", source_url=url,
                  reliability=Reliability.AUTHORITATIVE,
                  correlation_group=f"analytics|{domain}")
            for i in ids
        ]
        return ToolResult("extract_analytics_ids", True,
                          structured={"domain": domain, "identifiers": ids},
                          trust=Trust.SUBJECT, source_url=url, claims=claims)

    def _reverse(self, identifier: str) -> ToolResult:
        if self.index is None:
            return ToolResult("reverse_lookup_identifier", False,
                              error="no corpus index configured",
                              trust=Trust.THIRD_PARTY)
        scheme, _, value = identifier.partition(":")
        domains = self.index.domains_for_analytics(scheme, value)
        holders = len(domains)
        note = ("high selectivity: this looks like one operator's portfolio"
                if 1 < holders <= 150 else
                "low selectivity: a platform artifact, not a portfolio"
                if holders > 150 else "only one holder observed")
        return ToolResult("reverse_lookup_identifier", True,
                          structured={"identifier": identifier, "holders": holders,
                                      "domains": domains[:50]},
                          trust=Trust.THIRD_PARTY,
                          source_url=f"index://{identifier}", notes=[note])

    def _gleif(self, org_name: str) -> ToolResult:
        url = ("https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]="
               + org_name.replace(" ", "%20"))
        body = self.fetcher.get_text(url)
        if body is None:
            return ToolResult("lookup_gleif", False, error="not retrievable",
                              trust=Trust.REGISTRY, source_url=url)
        data = json.loads(body)
        recs = []
        claims = []
        for rec in data.get("data", [])[:3]:
            ent = rec.get("attributes", {}).get("entity", {})
            addr = ent.get("legalAddress", {})
            recs.append({
                "lei": rec.get("id"),
                "legal_name": (ent.get("legalName") or {}).get("name"),
                "jurisdiction": ent.get("jurisdiction"),
                "registered_as": ent.get("registeredAs"),
                "address": ", ".join(filter(None, [
                    " ".join(addr.get("addressLines", []) or []),
                    addr.get("city"), addr.get("country")])),
            })
            if rec.get("id"):
                claims.append(Claim(
                    subject=Identifier(IdKind.ORG_NAME, org_name),
                    predicate=Predicate.SAME_AS,
                    object=Identifier(IdKind.LEI, rec["id"]),
                    collector="agent:lookup_gleif", source_url=url,
                    reliability=Reliability.AUTHORITATIVE,
                    correlation_group=f"gleif|{rec['id']}"))
        return ToolResult("lookup_gleif", True, structured={"records": recs},
                          trust=Trust.REGISTRY, source_url=url, claims=claims)

    def _companies_house(self, company_number: str) -> ToolResult:
        url = f"https://api.company-information.service.gov.uk/company/{company_number}/officers"
        body = self.fetcher.get_text(url)
        if body is None:
            return ToolResult("lookup_companies_house", False, error="not retrievable",
                              trust=Trust.REGISTRY, source_url=url)
        data = json.loads(body)
        officers = [{"name": i.get("name"), "role": i.get("officer_role"),
                     "appointed_on": i.get("appointed_on")}
                    for i in data.get("items", []) if i.get("name")]
        claims = [
            Claim(subject=Identifier(IdKind.PERSON_NAME, o["name"]),
                  predicate=Predicate.OFFICER_OF,
                  object=Identifier(IdKind.COMPANY_NUMBER, f"gb/{company_number}"),
                  collector="agent:lookup_companies_house", source_url=url,
                  reliability=Reliability.AUTHORITATIVE,
                  correlation_group=f"ch|{company_number}")
            for o in officers
        ]
        return ToolResult("lookup_companies_house", True,
                          structured={"company_number": company_number,
                                      "officers": officers},
                          trust=Trust.REGISTRY, source_url=url, claims=claims)

    def _rdap(self, domain: str) -> ToolResult:
        url = f"https://rdap.org/domain/{domain}"
        body = self.fetcher.get_text(url)
        if body is None:
            return ToolResult("lookup_rdap", False, error="not retrievable",
                              trust=Trust.REGISTRY, source_url=url)
        data = json.loads(body)
        entities = []
        for ent in data.get("entities", []):
            vals = [i[3] for i in (ent.get("vcardArray") or [None, []])[1] or []
                    if isinstance(i, list) and len(i) >= 4 and isinstance(i[3], str)]
            entities.append({"roles": ent.get("roles", []), "values": vals})
        return ToolResult("lookup_rdap", True, structured={"entities": entities},
                          trust=Trust.REGISTRY, source_url=url)
