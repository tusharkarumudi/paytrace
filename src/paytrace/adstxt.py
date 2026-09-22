"""ads.txt account classification: separating real relationships from paste.

## The problem with DIRECT

Many ad networks hand publishers a block of ads.txt lines and tell them to paste
it in. The result is that a ``DIRECT`` label may represent the publisher's own
account, or the network's direct relationship one layer up, or a partner's two
layers up. The same seller IDs then appear across tens of thousands of unrelated
domains.

Treating every ``DIRECT`` record as evidence of a relationship is therefore
wrong, and wrong in the direction that manufactures false attributions: two
sites sharing four hundred pasted records look identical and have nothing to do
with each other.

A typical publisher ads.txt has several hundred records. **One to five of them
are the publisher's actual accounts.** Finding those is the entire problem; the
rest is noise that has to be positively identified as noise rather than
optimistically included.

## What actually discriminates

Not the label. Four things, in order of strength:

1. **Rarity.** An account on 4 domains is an account. An account on 40,000
   domains is a template line. This is the selectivity model applied to the
   monetization layer, and it needs a corpus.
2. **Reciprocity.** ``sellers.json`` naming this domain back requires control of
   both sides. A pasted line is not reciprocated for the site that pasted it.
3. **Self-declaration.** ``OWNERDOMAIN`` and ``MANAGERDOMAIN`` are statements
   about the operator, published because DSPs penalise their absence.
4. **Certification.** The certification authority ID (TAG-ID) ties a record to a
   certified entity rather than to a string someone copied.

## Template detection

Two domains sharing a large account set are usually sharing a *template*, not an
operator. The discriminator is what remains after removing accounts that appear
widely:

    shared accounts:            412
    shared after boilerplate:     3   <- this is the signal
    jaccard on rare accounts:  0.75

An overlap of 412 that collapses to 0 rare accounts is two sites that pasted the
same network block. An overlap of 3 rare accounts shared by nobody else is an
operator.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum

# --------------------------------------------------------------------------- #
# Thresholds
# --------------------------------------------------------------------------- #

#: Above this many holder domains an account is treated as template boilerplate.
#: Deliberately low: large publishers legitimately share sales houses, but the
#: cost of a false "boilerplate" call is one missed lead, while the cost of a
#: false "rare" call is a fabricated portfolio.
BOILERPLATE_THRESHOLD = 150

#: Below this, an account is discriminating enough to anchor an attribution.
RARE_THRESHOLD = 25

#: An ads.txt with more records than this is almost certainly aggregating
#: network templates rather than declaring relationships.
LARGE_FILE_RECORDS = 200


class AccountClass(StrEnum):
    PUBLISHER = "publisher_account"    # rare, reciprocated, seller_type PUBLISHER
    LIKELY_OWNED = "likely_owned"      # rare and DIRECT, reciprocity unconfirmed
    INTERMEDIARY = "intermediary"      # reciprocated but seller_type INTERMEDIARY
    RESELLER_CHAIN = "reseller_chain"  # RESELLER record
    BOILERPLATE = "boilerplate"        # widely duplicated; carries no signal
    UNKNOWN = "unknown"                # no corpus to judge against


#: Scoring weight by class. BOILERPLATE is zero, not small: a line present on
#: forty thousand domains is not weak evidence, it is no evidence.
CLASS_WEIGHT: dict[AccountClass, float] = {
    AccountClass.PUBLISHER: 1.0,
    AccountClass.LIKELY_OWNED: 0.6,
    AccountClass.INTERMEDIARY: 0.3,
    AccountClass.RESELLER_CHAIN: 0.15,
    AccountClass.BOILERPLATE: 0.0,
    AccountClass.UNKNOWN: 0.2,
}


@dataclass(frozen=True)
class Account:
    """One ads.txt record, in well-known.dev's account form."""

    adsystem: str
    seller_id: str
    relationship: str = "DIRECT"
    cid: str = ""                      # certification authority ID (TAG-ID)
    inline_comment: str = ""

    @property
    def key(self) -> str:
        return f"{self.adsystem}|{self.seller_id}"

    @property
    def is_direct(self) -> bool:
        return self.relationship == "DIRECT"


@dataclass
class AccountAssessment:
    account: Account
    klass: AccountClass
    holders: int = 0
    reciprocated: bool | None = None
    seller_type: str = ""
    seller_domain: str = ""
    reasons: list[str] = field(default_factory=list)

    @property
    def weight(self) -> float:
        return CLASS_WEIGHT[self.klass]

    @property
    def discriminating(self) -> bool:
        return self.klass in (AccountClass.PUBLISHER, AccountClass.LIKELY_OWNED)

    def render(self) -> str:
        recip = {True: "reciprocated", False: "NOT reciprocated",
                 None: "reciprocity unknown"}[self.reciprocated]
        return (f"{self.account.key} [{self.account.relationship}] "
                f"-> {self.klass.value} (holders={self.holders}, {recip})")


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

_VARIABLE = re.compile(
    r"^\s*(OWNERDOMAIN|MANAGERDOMAIN|CONTACT|SUBDOMAIN|INVENTORYPARTNERDOMAIN)"
    r"\s*=\s*([^\s#]+)\s*(?:#(.*))?$", re.I)

#: Placeholder records signal an unmaintained or templated file.
_PLACEHOLDER = re.compile(r"placeholder|example\.com|yourdomain|REPLACE", re.I)


@dataclass
class AdsTxt:
    """A parsed ads.txt, in the shape well-known.dev exposes."""

    domain: str
    accounts: list[Account] = field(default_factory=list)
    variables: dict[str, list[str]] = field(default_factory=dict)
    variable_comments: dict[str, str] = field(default_factory=dict)
    standalone_comments: list[str] = field(default_factory=list)
    has_placeholder: bool = False
    is_app_ads: bool = False

    # -- well-known.dev style stats ------------------------------------------ #

    @property
    def record_count(self) -> int:
        return len(self.accounts)

    @property
    def account_count(self) -> int:
        return len({a.key for a in self.accounts})

    @property
    def direct_count(self) -> int:
        return len({a.key for a in self.accounts if a.is_direct})

    @property
    def reseller_count(self) -> int:
        return len({a.key for a in self.accounts if not a.is_direct})

    @property
    def system_count(self) -> int:
        return len({a.adsystem for a in self.accounts})

    @property
    def owner_domain(self) -> str:
        v = self.variables.get("OWNERDOMAIN", [])
        return v[0] if v else ""

    @property
    def manager_domains(self) -> list[str]:
        return self.variables.get("MANAGERDOMAIN", [])

    @property
    def looks_aggregated(self) -> bool:
        """A file this large is aggregating network templates, not declaring
        relationships."""
        return self.record_count > LARGE_FILE_RECORDS

    def template_fingerprint(self) -> str:
        """Stable hash of the account set. Identical fingerprints across
        unrelated domains are the signature of a shared template."""
        keys = sorted({f"{a.key}|{a.relationship}" for a in self.accounts})
        return hashlib.sha256("\n".join(keys).encode()).hexdigest()[:16]


def parse(body: str, domain: str = "", is_app_ads: bool = False) -> AdsTxt:
    out = AdsTxt(domain=domain, is_app_ads=is_app_ads)

    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("#"):
            comment = stripped.lstrip("#").strip()
            if comment:
                out.standalone_comments.append(comment)
            continue

        if m := _VARIABLE.match(stripped):
            name, value, comment = m.group(1).upper(), m.group(2), m.group(3)
            out.variables.setdefault(name, []).append(value.strip().lower())
            if comment and comment.strip():
                out.variable_comments[name] = comment.strip()
            continue

        payload, _, inline = stripped.partition("#")
        parts = [p.strip() for p in payload.split(",")]
        if len(parts) < 3 or "." not in parts[0]:
            continue

        relationship = parts[2].upper()
        if relationship not in ("DIRECT", "RESELLER"):
            continue

        if _PLACEHOLDER.search(payload):
            out.has_placeholder = True
            continue

        out.accounts.append(Account(
            adsystem=parts[0].lower(),
            seller_id=parts[1],
            relationship=relationship,
            cid=parts[3].strip() if len(parts) > 3 else "",
            inline_comment=inline.strip(),
        ))

    return out


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #

def classify_account(
    account: Account,
    *,
    holders: int | None = None,
    reciprocated: bool | None = None,
    seller_type: str = "",
    seller_domain: str = "",
    subject_domain: str = "",
    owner_domain: str = "",
) -> AccountAssessment:
    """Classify one account. ``holders`` is the corpus count; without it the
    verdict is UNKNOWN rather than optimistic."""
    reasons: list[str] = []

    if holders is None:
        return AccountAssessment(
            account, AccountClass.UNKNOWN, 0, reciprocated, seller_type,
            seller_domain,
            ["no corpus index — cannot distinguish an account from a template line"])

    if holders > BOILERPLATE_THRESHOLD:
        reasons.append(
            f"present on {holders} domains — a pasted network template line, "
            "not a declared relationship")
        return AccountAssessment(account, AccountClass.BOILERPLATE, holders,
                                 reciprocated, seller_type, seller_domain, reasons)

    if not account.is_direct:
        reasons.append("RESELLER record: describes a supply path, not ownership")
        return AccountAssessment(account, AccountClass.RESELLER_CHAIN, holders,
                                 reciprocated, seller_type, seller_domain, reasons)

    if holders <= RARE_THRESHOLD:
        reasons.append(f"rare: only {holders} domain(s) declare this account")

    if reciprocated is False:
        reasons.append(
            "sellers.json does not name this domain — the DIRECT label is "
            "unreciprocated and may have been copied")
        return AccountAssessment(account, AccountClass.RESELLER_CHAIN, holders,
                                 reciprocated, seller_type, seller_domain, reasons)

    st = (seller_type or "").upper()
    if reciprocated and st == "PUBLISHER":
        reasons.append("sellers.json names this domain with seller_type PUBLISHER")
        if owner_domain and seller_domain and seller_domain.endswith(owner_domain):
            reasons.append("seller domain matches the declared OWNERDOMAIN")
        return AccountAssessment(account, AccountClass.PUBLISHER, holders,
                                 reciprocated, seller_type, seller_domain, reasons)

    if reciprocated and st in ("INTERMEDIARY", "BOTH"):
        reasons.append(f"reciprocated but seller_type is {st}")
        return AccountAssessment(account, AccountClass.INTERMEDIARY, holders,
                                 reciprocated, seller_type, seller_domain, reasons)

    if holders <= RARE_THRESHOLD:
        reasons.append("DIRECT and rare, but reciprocity unconfirmed")
        return AccountAssessment(account, AccountClass.LIKELY_OWNED, holders,
                                 reciprocated, seller_type, seller_domain, reasons)

    reasons.append(f"DIRECT but present on {holders} domains — inconclusive")
    return AccountAssessment(account, AccountClass.RESELLER_CHAIN, holders,
                             reciprocated, seller_type, seller_domain, reasons)


# --------------------------------------------------------------------------- #
# Overlap
# --------------------------------------------------------------------------- #

@dataclass
class Overlap:
    """Account overlap between two domains, boilerplate removed."""

    a: str
    b: str
    shared_total: int
    shared_rare: int
    rare_keys: list[str]
    jaccard_all: float
    jaccard_rare: float
    same_fingerprint: bool = False

    @property
    def is_template_sharing(self) -> bool:
        """Large overlap that vanishes once boilerplate is removed."""
        return self.shared_total >= 20 and self.shared_rare == 0

    @property
    def is_operator_signal(self) -> bool:
        return self.shared_rare >= 1

    def render(self) -> str:
        if self.same_fingerprint:
            verdict = "IDENTICAL FILE — same template, not evidence of control"
        elif self.is_template_sharing:
            verdict = ("shared template only — the overlap collapses to nothing "
                       "once widely-duplicated accounts are removed")
        elif self.is_operator_signal:
            verdict = (f"{self.shared_rare} rare account(s) in common: "
                       f"{', '.join(self.rare_keys[:5])}")
        else:
            verdict = "no meaningful overlap"
        return (f"{self.a} <-> {self.b}: {self.shared_total} shared "
                f"({self.shared_rare} rare) — {verdict}")


def compare_domains(
    a: AdsTxt, b: AdsTxt, holder_lookup,
) -> Overlap:
    """Compare two ads.txt files, discounting boilerplate.

    ``holder_lookup(adsystem, seller_id) -> int`` supplies corpus counts.

    This is the function that stops two sites which pasted the same network
    block from resolving as one operator.
    """
    ka = {x.key for x in a.accounts}
    kb = {x.key for x in b.accounts}
    shared = ka & kb
    union = ka | kb

    rare = [k for k in shared
            if holder_lookup(*k.split("|", 1)) <= BOILERPLATE_THRESHOLD]
    rare_union = [k for k in union
                  if holder_lookup(*k.split("|", 1)) <= BOILERPLATE_THRESHOLD]

    return Overlap(
        a=a.domain, b=b.domain,
        shared_total=len(shared),
        shared_rare=len(rare),
        rare_keys=sorted(rare),
        jaccard_all=len(shared) / len(union) if union else 0.0,
        jaccard_rare=len(rare) / len(rare_union) if rare_union else 0.0,
        same_fingerprint=a.template_fingerprint() == b.template_fingerprint(),
    )


# --------------------------------------------------------------------------- #
# The headline operation
# --------------------------------------------------------------------------- #

@dataclass
class KeyAccounts:
    domain: str
    discriminating: list[AccountAssessment] = field(default_factory=list)
    boilerplate_count: int = 0
    total: int = 0
    notes: list[str] = field(default_factory=list)

    def render(self) -> str:
        L = [f"{self.domain}: {self.total} record(s), "
             f"{self.boilerplate_count} boilerplate, "
             f"{len(self.discriminating)} discriminating"]
        if self.discriminating:
            L.append("")
            for a in self.discriminating:
                L.append(f"  {a.render()}")
                for r in a.reasons:
                    L.append(f"      {r}")
        else:
            L.append("  no discriminating accounts — this file declares nothing "
                     "that distinguishes it from the network templates it pastes")
        for n in self.notes:
            L.append(f"  note: {n}")
        return "\n".join(L)


def key_accounts(
    ads: AdsTxt,
    holder_lookup,
    reciprocity_lookup=None,
) -> KeyAccounts:
    """Reduce an ads.txt to the handful of accounts that actually identify it.

    Several hundred records typically collapse to one to five. Those are the
    ones worth pivoting on; everything else is a line the publisher was told to
    paste.
    """
    out = KeyAccounts(domain=ads.domain, total=len(ads.accounts))

    for acct in ads.accounts:
        holders = holder_lookup(acct.adsystem, acct.seller_id)
        recip, stype, sdomain = (None, "", "")
        if reciprocity_lookup and holders is not None and holders <= BOILERPLATE_THRESHOLD:
            recip, stype, sdomain = reciprocity_lookup(acct.adsystem, acct.seller_id)

        a = classify_account(
            acct, holders=holders, reciprocated=recip, seller_type=stype,
            seller_domain=sdomain, subject_domain=ads.domain,
            owner_domain=ads.owner_domain)

        if a.klass is AccountClass.BOILERPLATE:
            out.boilerplate_count += 1
        elif a.discriminating:
            out.discriminating.append(a)

    out.discriminating.sort(key=lambda a: (a.holders, a.account.key))

    if ads.looks_aggregated:
        out.notes.append(
            f"{ads.record_count} records — this file aggregates network "
            "templates; DIRECT labels in it are not reliable on their own")
    if ads.has_placeholder:
        out.notes.append("placeholder records present — file appears unmaintained")
    if ads.owner_domain:
        out.notes.append(f"OWNERDOMAIN={ads.owner_domain} (self-declared, "
                         "and the strongest thing in the file)")
    return out


#: Public alias — `parse` is too generic at package level.
parse_ads_txt = parse
