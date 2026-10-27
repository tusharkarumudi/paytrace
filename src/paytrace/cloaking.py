"""Differential retrieval: is this file the same for everyone?

The whole method rests on `ads.txt` being a public declaration. It is served
from the publisher's own origin, by software the publisher controls, and
nothing stops that software answering one thing to a crawler and another to a
browser. An operator who does that defeats every check downstream of the
retrieval, because every one of them is reasoning about a document that only
we were shown.

Until now nothing compared our copy against anyone else's, so the toolkit had
no way to notice. This module fetches the same file more than once, varying
one thing at a time, and compares what came back.

What varies, and what each variant proves:

- **a second declared egress** — same request, different exit. Catches
  selective serving by IP or ASN. No misrepresentation: the request is
  identical to the first one in every respect we control.
- **a browser User-Agent** — catches the common case, which is a rule keyed on
  the UA string. This one IS a misrepresentation, so it is opt-in and recorded
  in the audit trail with the string that was sent. A tool that claims an
  honest record while quietly lying about who it is would be worth less than
  one that cannot do the check at all.
- **the archived copy** — what the Internet Archive was served, at a time we
  did not choose. Weaker: `ads.txt` legitimately changes, so a difference here
  is a question, not a finding.

Comparison is on the SET of declared accounts, never on bytes. Two honest
copies of the same file differ constantly -- comment lines, record order,
trailing whitespace, a CRLF -- and a byte comparison would report cloaking on
every site in the world.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .adstxt import parse

#: A current, ordinary desktop browser. Used only when the caller asks for the
#: User-Agent variant, and recorded when it is.
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")

#: Verdicts, worst last.
CONSISTENT = "consistent"
COSMETIC = "cosmetic_differences"
MATERIAL = "DIFFERENT_ACCOUNTS"
UNVERIFIED = "unverified"


@dataclass(frozen=True)
class Variant:
    """One retrieval of the same file, and how it was obtained."""

    label: str
    accounts: frozenset[tuple[str, str, str]]
    owner_domain: str
    record_count: int
    body_sha256: str = ""
    ok: bool = True
    note: str = ""


@dataclass
class CloakingReport:
    domain: str
    verdict: str = UNVERIFIED
    variants: list[Variant] = field(default_factory=list)
    #: Accounts present in one variant and absent from another, as
    #: "label: adsystem/seller_id (RELATIONSHIP)".
    differences: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    #: True when a variant misrepresented the client. Recorded, always.
    misrepresented: bool = False

    @property
    def cloaked(self) -> bool:
        return self.verdict == MATERIAL

    def summary(self) -> str:
        if self.verdict == UNVERIFIED:
            return (f"{self.domain}: not verified — "
                    + (self.reasons[0] if self.reasons else "no second copy"))
        if self.verdict == CONSISTENT:
            return (f"{self.domain}: the same accounts were declared to "
                    f"{len(self.variants)} different retrievals")
        if self.verdict == COSMETIC:
            return (f"{self.domain}: same accounts, different bytes "
                    "(comments, order or whitespace) — not selective serving")
        return (f"{self.domain}: DIFFERENT ACCOUNTS were declared to different "
                f"retrievals. {len(self.differences)} difference(s); the "
                "declaration is not the same for everyone")


def account_set(body: str, domain: str = "") -> frozenset[tuple[str, str, str]]:
    """The comparable content of an ads.txt: who is declared, and how.

    Comments, ordering, whitespace and the certification-authority field are
    deliberately excluded. What matters is which ad systems are named, under
    which seller IDs, with which relationship -- the three things every
    downstream conclusion is drawn from.
    """
    doc = parse(body, domain)
    return frozenset((a.adsystem.lower(), a.seller_id, a.relationship.upper())
                     for a in doc.accounts)


def _fmt(account: tuple[str, str, str]) -> str:
    adsystem, seller_id, relationship = account
    return f"{adsystem}/{seller_id} ({relationship})"


def compare(variants: list[Variant]) -> CloakingReport:
    """Compare two or more retrievals of the same file."""
    report = CloakingReport(domain="")
    report.variants = list(variants)
    usable = [v for v in variants if v.ok]
    report.misrepresented = any("browser" in v.label for v in variants)

    if len(usable) < 2:
        report.verdict = UNVERIFIED
        report.reasons.append(
            "fewer than two retrievals succeeded, so there is nothing to "
            "compare: a single copy cannot show whether it is the copy "
            "everyone gets")
        return report

    first = usable[0]
    for other in usable[1:]:
        only_first = first.accounts - other.accounts
        only_other = other.accounts - first.accounts
        for a in sorted(only_first):
            report.differences.append(
                f"declared to {first.label} but NOT to {other.label}: {_fmt(a)}")
        for a in sorted(only_other):
            report.differences.append(
                f"declared to {other.label} but NOT to {first.label}: {_fmt(a)}")
        if first.owner_domain != other.owner_domain:
            report.differences.append(
                f"OWNERDOMAIN differs: {first.label} was told "
                f"{first.owner_domain or '(none)'}, {other.label} was told "
                f"{other.owner_domain or '(none)'}")

    if report.differences:
        report.verdict = MATERIAL
        report.reasons.append(
            "the set of declared accounts depends on who is asking. Every "
            "conclusion drawn from this file describes the copy we were shown, "
            "not the file the site publishes")
        return report

    if len({v.body_sha256 for v in usable if v.body_sha256}) > 1:
        report.verdict = COSMETIC
        report.reasons.append(
            "the bytes differ but the declared accounts do not: comments, "
            "record order or whitespace. Not selective serving")
        return report

    report.verdict = CONSISTENT
    return report


async def check_cloaking(
    fetcher,
    domain: str,
    *,
    browser_ua: str = "",
    egress_labels: tuple[str, ...] = (),
    path: str = "ads.txt",
) -> CloakingReport:
    """Retrieve ``path`` several ways and compare the declarations.

    ``browser_ua`` opts into the User-Agent variant and is the string sent;
    pass ``BROWSER_UA`` for the default. ``egress_labels`` names declared
    egresses to retrieve from in addition to the default one.

    Every retrieval goes through the ordinary fetcher, so each one is subject
    to the same policy and SSRF checks and each one lands in the evidence
    package. A check whose own requests were exempt from the controls would
    not be evidence of anything.
    """
    import hashlib

    url = f"https://{domain}/{path.lstrip('/')}"
    variants: list[Variant] = []

    async def one(label: str, headers: dict | None, egress: str) -> None:
        try:
            r = await fetcher.get(url, headers=headers, egress=egress)
        except Exception as e:                      # a check must not end a run
            variants.append(Variant(label, frozenset(), "", 0, ok=False,
                                    note=f"{type(e).__name__}: {e}"))
            return
        if r is None or getattr(r, "status", 0) != 200 or not getattr(r, "text", ""):
            variants.append(Variant(
                label, frozenset(), "", 0, ok=False,
                note=f"no usable body (status {getattr(r, 'status', 'none')})"))
            return
        doc = parse(r.text, domain)
        variants.append(Variant(
            label=label,
            accounts=account_set(r.text, domain),
            owner_domain=doc.owner_domain,
            record_count=doc.record_count,
            body_sha256=hashlib.sha256(r.text.encode("utf-8", "replace")
                                       ).hexdigest(),
        ))

    await one("this tool", None, "")
    for lbl in egress_labels:
        await one(f"egress {lbl}", None, lbl)
    if browser_ua:
        await one("a browser User-Agent", {"User-Agent": browser_ua}, "")

    report = compare(variants)
    report.domain = domain
    return report
