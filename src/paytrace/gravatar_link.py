"""Bind observed emails to observed Gravatar hashes, by arithmetic.

A WordPress page publishes an author's avatar as
``gravatar.com/avatar/<32 hex>``, and that hash is ``md5(lowercase(trim(
email)))``. So an email found anywhere in a case -- a git config, an OAuth
login hint, an imprint, a DMCA notice -- can be tested against every hash
found anywhere else, with no requests at all.

Two things this replaces:

- **Probing to establish a link.** The binding is a one-line computation over
  values already in hand. Asking gravatar.com about each discovered address to
  find out whether it matches a hash we already have is a request per address
  that answers a question arithmetic answers for free.
- **A hash mismatch that made the link impossible.** The Gravatar collector
  hashed emails with SHA-256 while every hash published in page markup is MD5,
  so an email and a page's hash for the same person could never match. The
  canonical implementation in ``fingerprint.py`` was written for exactly this
  comparison and was not being used.

**What a match does and does not establish.** md5(email) == hash means the
page displays *that address's* avatar. It does not mean the page's operator
controls the address: anyone can embed anyone's hash, and an operator who
wants to implicate someone needs only their email to do it. So these claims
are emitted with the correlation group of the page the hash came from, which
means they cannot act as independent corroboration of themselves, and they
are **not** definitional -- a planted hash must not bind a victim. The
arithmetic is certain; what it is evidence *of* rests on whoever put the hash
on the page.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from attribution_graph import (
    Claim,
    Identifier,
    IdKind,
    Predicate,
    Reliability,
)

from .fingerprint import gravatar_hash

#: What a hash looks like in markup. Anything else was never a Gravatar hash.
_HEX32 = 32


@dataclass
class LinkReport:
    emails: int = 0
    hashes: int = 0
    matched: list[tuple[str, str]] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    #: Requests made. Always zero, asserted by a test.
    requests: int = 0

    def summary(self) -> str:
        if not self.hashes or not self.emails:
            return (f"gravatar linking: nothing to compare "
                    f"({self.emails} email(s), {self.hashes} hash(es))")
        if not self.matched:
            return (f"gravatar linking: no match between {self.emails} "
                    f"observed email(s) and {self.hashes} observed hash(es)")
        return (f"gravatar linking: {len(self.matched)} email(s) bound to an "
                f"observed avatar hash by computation, with no requests")


def _provenance(graph, hash_value: str) -> tuple[str, str]:
    """The correlation group and source URL of whatever produced this hash.

    Reusing the group is the point: a computed restatement of an observed
    value is the same fact as the observation, so it must not count twice.
    Inventing a group here would turn one page into two independent sources.
    """
    want = hash_value.lower()
    group = source = ""
    for c in graph.claims:
        for side in (c.subject, c.object):
            if (isinstance(side, Identifier)
                    and side.kind is IdKind.GRAVATAR_HASH
                    and side.value.lower() == want):
                group = group or (c.correlation_group or "")
                source = source or (c.source_url or "")
                if group and source:
                    return group, source
    return group or f"gravatar|{want}", source


def link_gravatars(graph) -> LinkReport:
    """Match every observed email against every observed hash. No network.

    Both sides must have been **observed**. Nothing here generates an address
    to test: a candidate email invented from a name and a domain, hashed and
    matched, would manufacture a binding out of a guess and present it with
    the certainty of arithmetic.
    """
    report = LinkReport()

    emails: dict[str, Identifier] = {}
    hashes: dict[str, Identifier] = {}
    for ident in graph.identifiers.values():
        if ident.kind is IdKind.EMAIL and "@" in ident.value:
            emails[ident.value.strip().lower()] = ident
        elif ident.kind is IdKind.GRAVATAR_HASH and len(ident.value) == _HEX32:
            hashes[ident.value.lower()] = ident

    report.emails, report.hashes = len(emails), len(hashes)
    if not emails or not hashes:
        return report

    for address, email_id in sorted(emails.items()):
        digest = gravatar_hash(address)
        hash_id = hashes.get(digest)
        if hash_id is None:
            continue
        report.matched.append((address, digest))
        group, source = _provenance(graph, digest)
        report.claims.append(Claim(
            subject=hash_id,
            predicate=Predicate.SHARES_GRAVATAR,
            object=email_id,
            collector="gravatar_link",
            source_url=source or "computed: md5 of an observed address",
            # The computation is certain. Its evidential weight is not, which
            # is why the group below ties it to the page and why this
            # collector is deliberately absent from the engine's definitional
            # list: a hash placed on a page is placed by whoever controls it.
            # AUTHORITATIVE describes the computation, which is exact. It
            # grants nothing on its own: the engine's definitional carve-out
            # is keyed on the COLLECTOR name, and "gravatar_link" is
            # deliberately absent from that list, so this claim is scored like
            # any other single-source observation. A hash on a page is placed
            # by whoever controls the page.
            reliability=Reliability.AUTHORITATIVE,
            correlation_group=group,
            raw={
                "method": "md5(lowercase(trim(email))) == observed hash",
                "requests": 0,
                "caveat": "the page displays this address's avatar; it does "
                          "not follow that the page's operator controls the "
                          "address",
            },
        ))
    return report
