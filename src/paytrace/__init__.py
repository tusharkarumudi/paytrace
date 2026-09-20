"""paytrace: ad-tech supply-chain collectors for attribution-graph.

Turns the monetization layer into an attribution surface. An operator can hide
registrant, hosting and email; to be paid, a real legal entity must be named to
the ad system, and sellers.json publishes that name.
"""

from .adstxt import (
    Account,
    AccountClass,
    AdsTxt,
    KeyAccounts,
    Overlap,
    classify_account,
    compare_domains,
    key_accounts,
    parse_ads_txt,
)
from .catalog import Registry, coverage_report, federated_warning, load_catalog, query
from .collectors import build_all, registry
from .egress import (
    PROVIDERS,
    Egress,
    EgressPool,
    GeoDivergence,
    NetworkType,
    ProxyError,
    VantageCapture,
    redact,
    verify_egress_country,
)
from .enrich import (
    ROUTES_FOR,
    Expansion,
    Route,
    expand_from_name,
    name_variants,
    person_routes_available,
)
from .extract import (
    SENSITIVE_PATHS,
    Extraction,
    extract_artifacts,
    probe_sensitive_paths,
)
from .fingerprint import (
    CDN_RANGES,
    ContentFingerprint,
    FingerprintComparison,
    Resolution,
    cdn_for,
    compare_fingerprints,
    content_sha256,
    favicon_mmh3,
    fingerprint_content,
    gravatar_hash,
    hamming,
    resolve_host,
    simhash,
    similarity,
)
from .index import AdsTxtIndex, crawl_ads_txt, crawl_sellers_json
from .ingest import from_opencti_bundle, from_spiderfoot_csv, from_spiderfoot_db
from .net import Fetcher
from .pivot import PivotResult, Sibling, pivot_expand
from .robin_ingest import from_robin, to_handle_observations
from .sellersjson import (
    SELLERS_JSON_LOCATIONS,
    SellerNameKind,
    SellerRecord,
    classify_seller_name,
    find_seller_in_text,
    resolve_seller,
    sellers_json_url,
)

__version__ = "2.0.0"
__all__ = [
    "AdsTxtIndex", "crawl_ads_txt", "crawl_sellers_json",
    "Registry", "load_catalog", "query", "coverage_report", "federated_warning",
    "parse_ads_txt", "AdsTxt", "Account", "AccountClass", "classify_account",
    "SellerRecord", "SellerNameKind", "classify_seller_name", "resolve_seller",
    "expand_from_name", "Expansion", "Route", "ROUTES_FOR", "name_variants",
    "extract_artifacts", "Extraction", "gravatar_hash", "SENSITIVE_PATHS",
    "probe_sensitive_paths", "pivot_expand", "PivotResult", "Sibling",
    "person_routes_available",
    "Egress", "EgressPool", "NetworkType", "ProxyError", "PROVIDERS",
    "GeoDivergence", "VantageCapture", "redact", "verify_egress_country",
    "resolve_host", "Resolution", "cdn_for", "CDN_RANGES", "simhash",
    "hamming", "similarity", "content_sha256", "favicon_mmh3",
    "fingerprint_content", "ContentFingerprint", "compare_fingerprints",
    "FingerprintComparison",
    "find_seller_in_text", "sellers_json_url", "SELLERS_JSON_LOCATIONS",
    "key_accounts", "KeyAccounts", "compare_domains", "Overlap",
    "from_spiderfoot_csv", "from_spiderfoot_db", "from_opencti_bundle",
    "from_robin", "to_handle_observations",
    "Fetcher", "build_all", "registry", "__version__",
]
