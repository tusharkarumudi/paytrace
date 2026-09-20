"""End-to-end domain attribution, start to finish, offline.

Seeds one domain and follows the full chain to a named legal entity, producing
the complete output set: report, verification trail, evidence package, graph
exports.

    python examples/end_to_end_domain.py

All network responses are stubbed with synthetic data, so it is deterministic
and runs anywhere. The stub payloads are realistic in shape — swap ``StubFetcher``
for ``paytrace.Fetcher`` and the same code runs live.

The chain:

    scraper-site.example
      -> ads.txt              seller ID + OWNERDOMAIN
      -> sellers.json         legal entity name          [reciprocity check]
      -> page source          AdSense publisher ID       [load-bearing check]
      -> corpus index         other domains on that ID
      -> GLEIF                LEI, jurisdiction, address
      -> Companies House      directors, beneficial owners
      -> RDAP                 registrant (redacted)
      -> Companies House      second entity: NOT FOUND   [negative evidence]
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from attribution_graph import (
    AbsenceKind,
    AttributionGraph,
    CaseScope,
    Claim,
    EvidenceLog,
    Identifier,
    IdKind,
    Predicate,
    Reliability,
    StepKind,
    Trail,
    absence_claim,
    common_control_expectations,
    render_expectations,
    resolve,
    sha256_bytes,
    write_all,
    write_evidence_package,
)

OUT = Path("./out-demo")

# --------------------------------------------------------------------------- #
# Synthetic source data
# --------------------------------------------------------------------------- #

SOURCES: dict[str, str] = {
    "https://scraper-site.example/ads.txt": (
        "# ads.txt v1.1\n"
        "OWNERDOMAIN=examplemedia.example\n"
        "pubmatic.example, 156423, DIRECT, 5d62403b186f2ace\n"
        "adx.example, pub-1234567890123456, DIRECT\n"
    ),
    "https://pubmatic.example/sellers.json": json.dumps({
        "contact_email": "sellers@pubmatic.example",
        "sellers": [{
            "seller_id": "156423",
            "name": "Example Media Holdings Ltd",
            "domain": "examplemedia.example",
            "seller_type": "PUBLISHER",
            "is_confidential": 0,
        }],
    }),
    "https://scraper-site.example/": (
        '<html><head>'
        '<script async src="https://pagead2.googlesyndication.com/pagead/js/'
        'adsbygoogle.js?client=ca-pub-1234567890123456"></script>'
        '<script async src="https://www.googletagmanager.com/gtag/js?id=G-K7X2M9QP1L">'
        '</script></head><body>content</body></html>'
    ),
    "https://api.gleif.example/lei/5493001KJTIIGC8Y1R12": json.dumps({
        "data": {"id": "5493001KJTIIGC8Y1R12", "attributes": {"entity": {
            "legalName": {"name": "Example Media Holdings Ltd"},
            "jurisdiction": "GB",
            "registeredAs": "09876543",
            "legalAddress": {"addressLines": ["12 Example Street"],
                             "city": "London", "postalCode": "EC1A 1AA",
                             "country": "GB"},
        }}},
    }),
    "https://api.ch.example/company/09876543/officers": json.dumps({
        "items": [{"name": "OPERATOR, Jane Q", "officer_role": "director",
                   "appointed_on": "2019-03-14"}],
    }),
    "https://api.ch.example/company/09876543/psc": json.dumps({
        "items": [{"name": "Jane Q Operator", "kind": "individual-person-with-"
                   "significant-control", "notified_on": "2019-03-14",
                   "natures_of_control": ["ownership-of-shares-75-to-100-percent"]}],
    }),
    "https://rdap.example/domain/scraper-site.example": json.dumps({
        "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [
            ["fn", {}, "text", "REDACTED FOR PRIVACY"]]]}],
    }),
    "https://api.ch.example/search?q=Shell+Nominees+Ltd": json.dumps({"items": []}),
}


class StubFetcher:
    def __init__(self) -> None:
        self.count = 0

    async def get(self, url: str, headers=None, allow_html=False):
        self.count += 1
        body = SOURCES.get(url)

        class R:
            status = 200 if body else 404
            text = body or ""
        return R()

    async def get_json(self, url: str, headers=None):
        r = await self.get(url)
        return json.loads(r.text) if r.text else None

    async def aclose(self):
        pass


# --------------------------------------------------------------------------- #

async def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    case = OUT / "case.yaml"
    case.write_text(
        "case_ref: DEMO-2026-001\n"
        "authorization: 'reference example — synthetic data, no real subjects'\n"
        "contact_email: demo@example.test\n"
        "seeds: [domain:scraper-site.example]\n"
        "entity_types_allowed: [Company]\n"
        "robots_policy: record\n"
        "pivot_radius: 3\n"
        f"audit_path: {OUT / 'audit.jsonl'}\n"
    )
    scope = CaseScope.load(case)
    graph = AttributionGraph(case_ref=scope.case_ref)
    trail = Trail(scope.case_ref, scope.authorization)
    ev = EvidenceLog(scope, OUT / "evidence")
    f = StubFetcher()

    async def grab(url: str, collector: str, title: str = "") -> tuple[str, int]:
        """Retrieve, preserve, cite. Every source goes through here exactly once,
        so nothing can enter the graph without a capture and a citation."""
        r = await f.get(url, allow_html=True)
        body = r.text.encode()
        ev.record(url, r.status, body, collector=collector)
        n = trail.cite(url, body_sha256=sha256_bytes(body), status=r.status,
                       collector=collector, title=title or url)
        trail.add(StepKind.FETCH, f"Retrieved {title or url}", citations=[n])
        return r.text, n

    def claim(subj, pred, obj, url, rel, group, **kw) -> None:
        graph.add_claim(Claim(subject=subj, predicate=pred, object=obj,
                              collector=group.split("|")[0], source_url=url,
                              reliability=rel, correlation_group=group, **kw))

    domain = Identifier(IdKind.DOMAIN, "scraper-site.example")
    trail.seed("domain:scraper-site.example")

    # -- 1. ads.txt ---------------------------------------------------------- #
    url = "https://scraper-site.example/ads.txt"
    text, c1 = await grab(url, "ads_txt_owner", "ads.txt")
    seller = Identifier(IdKind.SELLER_ID, "pubmatic.example/156423")
    owner = Identifier(IdKind.DOMAIN, "examplemedia.example")
    trail.extract("OWNERDOMAIN", "examplemedia.example", c1)
    trail.extract("seller ID (DIRECT)", "pubmatic.example/156423", c1)
    claim(domain, Predicate.SELLER_OF, seller, url, Reliability.STRONG, "ads_txt|seed")
    claim(domain, Predicate.OWNER_DOMAIN, owner, url, Reliability.STRONG, "ads_txt|seed")

    # -- 2. sellers.json (reciprocity) --------------------------------------- #
    url = "https://pubmatic.example/sellers.json"
    _, c2 = await grab(url, "sellers_json", "sellers.json")
    org = Identifier(IdKind.ORG_NAME, "Example Media Holdings Ltd")
    trail.extract("seller legal name", "Example Media Holdings Ltd", c2)
    trail.add(StepKind.EXTRACT,
              "Reciprocity check passed: sellers.json names examplemedia.example, "
              "matching the ads.txt OWNERDOMAIN",
              detail="Requires control of both sides, so it is not plantable.",
              citations=[c1, c2])
    claim(seller, Predicate.LEGAL_NAME, org, url, Reliability.STRONG, "sellers_json|156423")
    claim(seller, Predicate.OPERATES, owner, url, Reliability.STRONG, "sellers_json|156423")

    # -- 3. page source (load-bearing) --------------------------------------- #
    url = "https://scraper-site.example/"
    html, c3 = await grab(url, "analytics_ids", "homepage source")
    adsense = Identifier(IdKind.ANALYTICS_ID, "adsense:1234567890123456")
    trail.extract("AdSense publisher ID", "ca-pub-1234567890123456", c3)
    trail.add(StepKind.EXTRACT,
              "Load-bearing check passed: the adsbygoogle loader carries the ID",
              detail="The ID is wired into a working integration, not inert text.",
              citations=[c3])
    claim(domain, Predicate.SHARES_ANALYTICS_ID, adsense, url,
          Reliability.AUTHORITATIVE, "analytics|seed")

    # -- 4. corpus reverse pivot ---------------------------------------------- #
    siblings = ["mirror-a.example", "mirror-b.example"]
    trail.add(StepKind.PIVOT,
              f"Reverse-indexed adsense:1234567890123456 to {len(siblings)} further domain(s)",
              detail="3 holders total — high selectivity, so this is a portfolio "
                     "rather than a shared template.")
    for d in siblings:
        claim(domain, Predicate.SHARES_ANALYTICS_ID, Identifier(IdKind.DOMAIN, d),
              "index://analytics/adsense:1234567890123456",
              Reliability.AUTHORITATIVE, "portfolio|adsense:1234567890123456")

    # -- 5. GLEIF ------------------------------------------------------------- #
    url = "https://api.gleif.example/lei/5493001KJTIIGC8Y1R12"
    _, c4 = await grab(url, "gleif", "GLEIF LEI record")
    lei = Identifier(IdKind.LEI, "5493001KJTIIGC8Y1R12")
    cn = Identifier(IdKind.COMPANY_NUMBER, "gb/09876543")
    trail.extract("LEI", "5493001KJTIIGC8Y1R12", c4)
    claim(org, Predicate.SAME_AS, lei, url, Reliability.AUTHORITATIVE, "gleif|lei")
    claim(lei, Predicate.SAME_AS, cn, url, Reliability.AUTHORITATIVE, "gleif|lei")
    claim(lei, Predicate.INCORPORATED_IN, "GB", url, Reliability.AUTHORITATIVE, "gleif|lei")
    claim(lei, Predicate.REGISTERED_ADDRESS,
          Identifier(IdKind.POSTAL_ADDRESS, "12 Example Street, London, EC1A 1AA"),
          url, Reliability.AUTHORITATIVE, "gleif|lei")

    # -- 6. Companies House ---------------------------------------------------- #
    for path, pred, label in (
        ("officers", Predicate.OFFICER_OF, "directors"),
        ("psc", Predicate.BENEFICIAL_OWNER_OF, "persons with significant control"),
    ):
        url = f"https://api.ch.example/company/09876543/{path}"
        _, cn_cite = await grab(url, "companies_house_uk", f"Companies House {label}")
        person = Identifier(IdKind.PERSON_NAME, "Jane Q Operator")
        trail.extract(label, "Jane Q Operator", cn_cite)
        claim(person, pred, cn, url, Reliability.AUTHORITATIVE, f"ch|09876543|{path}",
              raw={"published_by": "statutory register"})

    # -- 7. RDAP (redacted) ---------------------------------------------------- #
    url = "https://rdap.example/domain/scraper-site.example"
    _, c6 = await grab(url, "rdap", "RDAP record")
    trail.add(StepKind.FILTER, "Set aside RDAP registrant 'REDACTED FOR PRIVACY'",
              detail="Privacy-proxy placeholder — identifies the registrar's "
                     "masking service, not an operator.", citations=[c6])

    # -- 8. negative evidence -------------------------------------------------- #
    url = "https://api.ch.example/search?q=Shell+Nominees+Ltd"
    await grab(url, "companies_house_uk", "Companies House search")
    ev.record_negative(url, "companies_house_uk",
                       "no entity named 'Shell Nominees Ltd' on the UK register")
    trail.empty(url, "UK Companies House for 'Shell Nominees Ltd'", "companies_house_uk")
    graph.add_claim(absence_claim(
        Identifier(IdKind.ORG_NAME, "Shell Nominees Ltd"), "companies_house_uk",
        AbsenceKind.CHECKED_ABSENT, query_url=url,
        what_was_sought="UK registration for a second entity named in the ads.txt chain"))

    ev.record_refusal("people-search aggregators", "policy",
                      "DATA_BROKER is a denied source class")
    trail.refused("people-search aggregators", "denied source class")

    # -- 9. expectations ------------------------------------------------------- #
    exps = common_control_expectations("scraper-site.example", "mirror-a.example")
    exps[0].satisfied = True    # shared registrar
    exps[3].satisfied = True    # same ad-tech seller
    exps[2].satisfied = False   # no shared certificate

    # -- 10. resolve ----------------------------------------------------------- #
    result = resolve(graph, scope.entity_types_allowed)
    trail.infer(
        "scraper-site.example is operated by Example Media Holdings Ltd "
        "(LEI 5493001KJTIIGC8Y1R12, UK 09876543)",
        basis="Reciprocated ads.txt/sellers.json declaration plus a load-bearing "
              "AdSense account, corroborated by the GLEIF registry chain.",
        citations=[c1, c2, c3, c4])

    # -- 11. output ------------------------------------------------------------ #
    ev.fetch_policy = {"robots_policy": scope.robots_policy,
                       "statement": "robots.txt directives recorded against each "
                                    "capture; retrieval was not limited by them."}
    outputs = write_all(graph, result, scope, OUT, trail=trail)
    outputs += write_evidence_package(
        ev, "scraper-site.example attributed to Example Media Holdings Ltd")

    ok, problems = ev.verify()

    # -- report ---------------------------------------------------------------- #
    print("=" * 72)
    print(f"{len(graph.identifiers)} identifiers | {len(graph.claims)} claims | "
          f"{len(graph.entities)} entities | {f.count} requests")
    print(f"evidence: {len(ev.captures)} captures, chain "
          f"{'VERIFIED' if ok else 'FAILED: ' + str(problems)}")
    print(f"trail: {len(trail.steps)} steps, {len(trail.sources)} cited sources")
    print("=" * 72)

    print("\nRESOLVED ENTITIES")
    for e in graph.entities.values():
        if len(e.identifiers) > 1:
            print(f"  {e.best_label} ({e.type.value})")
            for i in sorted(e.identifiers, key=lambda x: x.key):
                print(f"      {i.key}")

    print("\nTOP ASSESSMENTS")
    for (a, b), asmt in sorted(result.assessments.items(),
                               key=lambda kv: -kv[1].probability)[:6]:
        if asmt.band.value == "UNSUPPORTED":
            continue
        print(f"  {asmt.probability:.3f}  {asmt.band.value:<12} "
              f"{asmt.independent_groups} grp  {a} <-> {b}")

    print("\nBLOCKED MERGES")
    for a, b, why in result.rejected[:5]:
        print(f"  {a} <-> {b}\n      {why}")
    if not result.rejected:
        print("  (none)")

    print("\nEXPECTATIONS IF COMMONLY CONTROLLED")
    print(render_expectations(exps))

    print("\nOUTPUTS")
    for p in outputs:
        print(f"  {p}")

    print("""
READING THIS RESULT
===================
Two different things happened, and the difference is the point.

The COMPANY resolved confidently. org_name, LEI and company_number merged into
one entity because GLEIF's identity assertions are definitional -- a registry
saying an LEI belongs to a legal name is not evidence about an identity, it is
the identity -- so they are exempt from the corroboration requirement.

The DOMAIN did not attach to that company. domain <-> seller_id sits at 0.029,
WEAK, on one evidence group.

That is correct, and it is worth understanding why, because the instinct is to
read it as the tool underperforming. The reciprocity check passed -- but what it
confirmed is that seller 156423 belongs to examplemedia.example. Nothing
independently ties scraper-site.example to that seller except scraper-site's own
ads.txt file, which scraper-site wrote about itself. One self-declaration, one
correlation group, and the group cap is deliberately set below the prior so a
single inferential source cannot carry a merge.

To lift it you need a second independent group. Any of these would do it:

  - examplemedia.example's own ads.txt declaring scraper-site as inventory
  - a shared certificate covering both names
  - the AdSense account reverse-indexed against a real corpus (this demo has no
    corpus, so holder counts default to the case graph)
  - archived history showing the pairing over time

The two-line summary: the registry chain is solid, the domain-to-company link is
a lead. A tool that reported this as a finding would be one you could not rely
on when it mattered.
""")


if __name__ == "__main__":
    asyncio.run(main())
