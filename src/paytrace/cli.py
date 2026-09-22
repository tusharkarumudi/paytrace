"""paytrace CLI: run an attribution case, or manage the corpus index."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from attribution_graph import (
    CaseScope,
    CompositeIndex,
    Engine,
    InMemoryIndex,
    PolicyError,
    load_blacklist,
    write_all,
)
from attribution_graph.evidence import secure_mkdir

# User-Agents derive from the package version so a bump can never
# leave a stale string behind. A patch bump previously left five
# User-Agents reporting the old version.
from ._version import __version__ as _VERSION  # noqa: E402
from .catalog import coverage_report, query
from .collectors import build_all
from .index import AdsTxtIndex
from .net import Fetcher


def _run(args: argparse.Namespace) -> int:
    # This command loads the same CaseScope as `attribution run` but builds a
    # bare Fetcher: no PolicyEngine, no EvidenceLog, no case egress. A case file
    # therefore meant different things depending on which binary read it, which
    # is the worst kind of difference -- invisible.
    #
    # Rather than maintain two orchestrations that drift, this one now states
    # what it is and points at the one that implements the full contract.
    print(
        "note: `paytrace run` is the collector-only path. It does NOT enforce\n"
        "      robots policy, does NOT write an evidence package, and does NOT\n"
        "      apply case-file egress. Use `attribution run` for the full\n"
        "      contract; this command is for collector development.\n",
        file=sys.stderr)
    try:
        scope = CaseScope.load(args.case)
    except PolicyError as e:
        print(f"policy error: {e}", file=sys.stderr)
        return 2

    if args.blacklist:
        load_blacklist(args.blacklist)

    ua = (f"paytrace/{_VERSION} (case {scope.case_ref}; "
          f"{scope.contact_email or 'no-contact-configured'})")
    fetcher = Fetcher(user_agent=ua, max_requests=scope.max_requests)
    enabled = set(args.collectors.split(",")) if args.collectors else None
    collectors = build_all(fetcher, scope, enabled)

    engine = Engine(scope, collectors=collectors, concurrency=args.concurrency)
    if args.index:
        # Composite needs the engine's graph, so it is attached after construction.
        engine.index = CompositeIndex(AdsTxtIndex(args.index), InMemoryIndex(engine.graph))
    else:
        print("warning: no --index given. Selectivity counts come from this case "
              "only, so confidence figures are upper bounds, not assessments.",
              file=sys.stderr)

    print(f"case {scope.case_ref} | auth {scope.authorization}")
    print(f"collectors: {', '.join(c.name for c in collectors)}")
    print(f"radius {scope.pivot_radius} | types "
          f"{', '.join(t.value for t in scope.entity_types_allowed)}")


    # One event loop for the work AND the cleanup. Closing the fetcher in a
    # second asyncio.run() fails on a real network -- its connections belong
    # to the first loop, now closed -- with "Event loop is closed". Mock
    # transports hold no such connections, which is why tests never saw it.
    async def _collect():
        try:
            return await engine.run()
        finally:
            await fetcher.aclose()

    result = asyncio.run(_collect())
    paths = write_all(engine.graph, result, scope, Path(args.out))

    print(f"\n{len(engine.graph.identifiers)} identifiers, "
          f"{len(engine.graph.claims)} claims, "
          f"{len(engine.graph.entities)} entities, "
          f"{fetcher.count} requests")
    for p in paths:
        print(f"  {p}")
    return 0


def _registries(args: argparse.Namespace) -> int:
    if args.coverage:
        print(coverage_report())
        return 0
    rows = query(
        jurisdiction=args.jurisdiction or None,
        category=args.category or None,
        yields=args.yields or None,
        automatable=True if args.automatable else None,
    )
    if not rows:
        print("no registries match")
        return 1
    for r in rows:
        key = f" [{r.auth_env}]" if r.needs_key else ""
        print(f"{r.jurisdiction:6} {r.name}")
        print(f"       access={r.access}{key}  status={r.status}")
        if r.url:
            print(f"       {r.url}")
        if r.yields:
            print(f"       yields: {', '.join(r.yields)}")
        if r.notes:
            print(f"       note: {r.notes.splitlines()[0]}")
        print()
    return 0


def _portfolio(args: argparse.Namespace) -> int:
    """Expand one seed domain to an actor's estate, then reconstruct registrants."""
    from .index import AdsTxtIndex
    from .portfolio import PortfolioExpander

    idx = AdsTxtIndex(args.index)
    fetcher = Fetcher(
        user_agent=f"paytrace/{_VERSION} (+https://github.com/tusharkarumudi/paytrace)",
        max_requests=args.max_requests,
    )
    exp = PortfolioExpander(idx, fetcher, use_wayback=not args.no_wayback)

    async def go():
        res = await exp.expand(args.domain, max_domains=args.max_domains)
        claims = []
        if args.registrants:
            claims = await exp.registrant_history(list(res.domains))
        await fetcher.aclose()
        return res, claims

    res, claims = asyncio.run(go())
    print(res.summary())

    if claims:
        print(f"\nregistrant leads ({len(claims)}):")
        pre = [c for c in claims if c.raw.get("pre_redaction")]
        for c in claims[:40]:
            era = ""
            if c.observed_at:
                era = f"  [{c.observed_at.strftime('%Y-%m')}]"
            flag = " *pre-redaction*" if c.raw.get("pre_redaction") else ""
            print(f"  {c.subject.value} -> {c.object_key}{era}{flag}")
        if pre:
            print(f"\n{len(pre)} observation(s) predate 2018 WHOIS redaction — "
                  "these are the highest-value leads in the set.")

    if args.out:
        out = Path(args.out)
        secure_mkdir(out)
        (out / "portfolio.json").write_text(json.dumps({
            "seed": res.seed,
            "domains": res.domains,
            "identifiers": res.identifiers,
            "rejected": res.rejected,
            "registrant_claims": [c.to_dict() for c in claims],
        }, indent=2, default=str))
        print(f"\n  {out / 'portfolio.json'}")
    return 0


def _keyaccounts(a: argparse.Namespace) -> int:
    """Reduce an ads.txt to the accounts that actually identify it."""
    import asyncio

    from .adstxt import key_accounts, parse
    from .index import AdsTxtIndex

    idx = AdsTxtIndex(a.index) if a.index else None
    if idx is None:
        print("warning: no --index. Without a corpus there is no way to tell an "
              "account from a pasted template line; every account will report "
              "as 'unknown'.", file=sys.stderr)

    fetcher = Fetcher(user_agent=f"paytrace/{_VERSION} (+keyaccounts)", max_requests=8)

    async def go():
        for path in ("ads.txt", "app-ads.txt"):
            r = await fetcher.get(f"https://{a.domain}/{path}")
            if r and r.status == 200 and r.text:
                yield path, r.text
        await fetcher.aclose()

    async def run():
        found = False
        async for path, body in go():
            found = True
            ads = parse(body, a.domain, is_app_ads=path == "app-ads.txt")
            print(f"\n=== {path} ===")
            print(key_accounts(
                ads,
                lambda s, i: idx.account_holders(s, i) if idx else None).render())
        if not found:
            print(f"no ads.txt or app-ads.txt at {a.domain}", file=sys.stderr)
            return 1
        return 0

    return asyncio.run(run())


def _check_concurrency(a) -> int | None:
    """Reject a non-positive concurrency before anything is constructed.

    `asyncio.Semaphore(0)` grants no permits, so a run does not degrade -- it
    hangs with no output and no timeout. Validating it in Engine covered one
    entry point; every CLI that exposes the flag is another.
    """
    n = getattr(a, "concurrency", None)
    if n is not None and n < 1:
        print(f"--concurrency must be at least 1, got {n}. A zero-permit "
              "semaphore hangs rather than disabling concurrency.",
              file=sys.stderr)
        return 2
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="paytrace", description="Ad-tech attribution")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run")
    r.add_argument("--case", required=True)
    r.add_argument("--out", default="./out")
    r.add_argument("--index", default="", help="corpus sqlite from `paytrace-index build`")
    r.add_argument("--collectors", default="")
    r.add_argument("--blacklist", default="")
    r.add_argument("--concurrency", type=int, default=6,

                   help="parallel collectors; must be >= 1")
    r.set_defaults(func=_run)

    g = sub.add_parser("registries", help="what registries exist, and can they be automated")
    g.add_argument("--jurisdiction", default="", help="ISO code, e.g. IN, GB, US")
    g.add_argument("--category", default="", choices=["", "corporate", "land",
                                                      "intellectual_property"])
    g.add_argument("--yields", default="", help="filter by yielded field, e.g. beneficial_owner")
    g.add_argument("--automatable", action="store_true")
    g.add_argument("--coverage", action="store_true", help="print full coverage report")
    g.set_defaults(func=_registries)

    pf = sub.add_parser("portfolio",
                        help="expand a seed domain to the actor's full estate")
    pf.add_argument("domain")
    pf.add_argument("--index", required=True, help="corpus sqlite")
    pf.add_argument("--out", default="")
    pf.add_argument("--max-domains", type=int, default=500)
    pf.add_argument("--max-requests", type=int, default=2000)
    pf.add_argument("--no-wayback", action="store_true")
    pf.add_argument("--registrants", action="store_true",
                    help="reconstruct current and pre-redaction registrant data")
    pf.set_defaults(func=_portfolio)

    k = sub.add_parser("keyaccounts",
                       help="reduce an ads.txt to the accounts that identify it")
    k.add_argument("domain")
    k.add_argument("--index", default="", help="corpus sqlite (strongly advised)")
    k.set_defaults(func=_keyaccounts)

    args = ap.parse_args(argv)
    _bad = _check_concurrency(args)
    if _bad is not None:
        return _bad
    return args.func(args)


def _cli() -> int:
    """Entry point tolerant of a truncated pipe (`paytrace registries | head`)."""
    import contextlib
    import os
    try:
        return main()
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 0
    except KeyboardInterrupt:
        with contextlib.suppress(Exception):
            print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(_cli())


