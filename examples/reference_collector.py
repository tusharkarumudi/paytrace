"""Reference collector — a working template for the Collector protocol.

Copy this file, rename the class, and fill in ``collect()``. Everything below is
either required by the protocol or a decision you will have to make anyway; the
comments explain what each choice costs you if you get it wrong.

Run it:

    python examples/reference_collector.py

It uses a stub fetcher, so it runs offline and demonstrates the full path from
raw source data to a scored assessment.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterable

from attribution_graph import (
    AttributionGraph,
    Claim,
    EntityType,
    Identifier,
    IdKind,
    Predicate,
    Reliability,
    SourceClass,
    assess,
    resolve,
)

from paytrace.collectors.base import Collector, register

# =========================================================================== #
# The collector
# =========================================================================== #

@register                      # makes it discoverable by build_all()
class ExampleRegistry(Collector):
    """One collector against one source.

    The four class attributes are the protocol. Everything else is yours.
    """

    # --- 1. Identity ------------------------------------------------------- #
    # Goes into every claim's provenance and appears in reports, so make it
    # stable. Renaming it later orphans historical evidence.
    name = "example_registry"

    # --- 2. Source class --------------------------------------------------- #
    # Checked against the deny list when the Engine is constructed. A collector
    # declaring DATA_BROKER, BREACH_CORPUS, AUTHENTICATED_SCRAPE, BIOMETRIC or
    # LOCATION_BROKER raises at load — not at call, so a run cannot get halfway
    # in before discovering it.
    source_class = SourceClass.PUBLIC_REGISTRY

    # --- 3. Accepted inputs ------------------------------------------------ #
    # The engine only dispatches identifiers of these kinds to you. Declaring a
    # kind you cannot actually handle wastes budget on calls that return [].
    accepts = (IdKind.ORG_NAME, IdKind.COMPANY_NUMBER)

    # --- 4. Priority ------------------------------------------------------- #
    # P1..P5, lower runs first. Put high-selectivity sources early: they collapse
    # the hypothesis space, and everything after them searches a smaller one.
    priority = 2

    # Optional: env var for an API key. Return [] when absent rather than
    # raising, so a run without the key degrades instead of dying.
    needs_key = None

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        """Query the source, return claims. Never raise on bad data.

        The engine catches exceptions and logs them, but a collector that fails
        is a silently weaker conclusion — so handle what you can predict.
        """
        url = f"https://registry.example/api/v1/search?q={ident.value}"

        # self.fetcher is rate-limited, cached and budget-capped. Use it rather
        # than httpx directly, or your requests bypass all three.
        data = await self.fetcher.get_json(url)
        if not data:
            return []

        claims: list[Claim] = []

        for record in data.get("results", [])[:5]:
            reg_no = record.get("registration_number")
            if not reg_no:
                continue

            subject = Identifier(IdKind.COMPANY_NUMBER, f"xx/{reg_no}")

            # ---- correlation_group: the decision that matters most --------- #
            #
            # It defines what counts as ONE observation. Everything this
            # collector learned from a single record came from one query
            # against one filing, so it is one group.
            #
            # Get this wrong and the scoring model breaks in a specific way:
            # emit N claims from one fact in N groups and they accumulate as if
            # independently confirmed, driving the posterior to certainty on
            # something you observed once. This is the single most common way
            # attribution tooling produces confident false results.
            group = f"{self.name}|{reg_no}"

            if record.get("legal_name"):
                claims.append(self.claim(
                    subject,
                    Predicate.LEGAL_NAME,
                    Identifier(IdKind.ORG_NAME, record["legal_name"]),
                    url,
                    # ---- reliability: be honest -------------------------- #
                    # AUTHORITATIVE means a statutory registry or a
                    # cryptographic binding. Self-declared data is STRONG at
                    # best. Regex over scraped HTML is MODERATE or WEAK.
                    # Overstating it is how a weak signal ends up carrying a
                    # finding.
                    reliability=Reliability.AUTHORITATIVE,
                    correlation_group=group,
                ))

            # Officers of one company come from one filing. Same group.
            for officer in record.get("officers", [])[:20]:
                if not officer.get("name"):
                    continue
                claims.append(self.claim(
                    Identifier(IdKind.PERSON_NAME, officer["name"]),
                    # OFFICER_OF is a relationship BETWEEN entities. The
                    # resolver treats it as must-not-link, so a director never
                    # merges into the company they direct — a merge that plain
                    # graph traversal makes almost inevitable.
                    Predicate.OFFICER_OF,
                    subject,
                    url,
                    reliability=Reliability.AUTHORITATIVE,
                    correlation_group=group,
                    raw={"role": officer.get("role")},
                ))

            if record.get("address"):
                claims.append(self.claim(
                    subject,
                    Predicate.REGISTERED_ADDRESS,
                    Identifier(IdKind.POSTAL_ADDRESS, record["address"]),
                    url,
                    reliability=Reliability.AUTHORITATIVE,
                    correlation_group=group,
                ))

        return claims


# =========================================================================== #
# Running it
# =========================================================================== #

class StubFetcher:
    """Stands in for the real Fetcher so this file runs offline."""

    def __init__(self) -> None:
        self.count = 0

    async def get_json(self, url: str, headers: dict | None = None):
        self.count += 1
        return {
            "results": [{
                "registration_number": "09876543",
                "legal_name": "Example Media Holdings Ltd",
                "address": "12 Example Street, London, EC1A 1AA",
                "officers": [
                    {"name": "Jane Q Operator", "role": "director"},
                    {"name": "Sam Placeholder", "role": "secretary"},
                ],
            }]
        }

    async def get(self, url: str, headers: dict | None = None, allow_html: bool = False):
        return None

    async def aclose(self) -> None:
        pass


class StubScope:
    case_ref = "REF-DEMO"
    authorization = "reference example, synthetic data"

    def audit(self, *a, **k):
        pass


async def main() -> None:
    collector = ExampleRegistry(StubFetcher(), StubScope())

    claims = list(await collector.collect(Identifier(IdKind.ORG_NAME, "Example Media")))

    print(f"{len(claims)} claims from 1 source record\n")
    for c in claims:
        print(f"  {c.subject.key}")
        print(f"    --{c.predicate.value}--> {c.object_key}")
        print(f"    reliability={float(c.reliability):.2f}  group={c.correlation_group}")

    groups = {c.correlation_group for c in claims}
    print(f"\n{len(claims)} claims occupy {len(groups)} correlation group(s).")
    print("One filing is one observation, so they must not accumulate as if "
          "independently confirmed.\n")

    # Score them as the engine would.
    graph = AttributionGraph(case_ref="REF-DEMO")
    for c in claims:
        graph.add_claim(c)

    linking = [c for c in claims if c.predicate is Predicate.LEGAL_NAME]
    a = assess(linking, graph.holders)
    print("Assessment of the company-number <-> legal-name link:")
    print(json.dumps(a.to_dict(), indent=2))

    resolve(graph, {EntityType.COMPANY})
    print(f"\nResolved into {len(graph.entities)} entity/entities.")
    print("Note the directors did NOT merge into the company: OFFICER_OF is a "
          "must-not-link relation.")


if __name__ == "__main__":
    asyncio.run(main())
