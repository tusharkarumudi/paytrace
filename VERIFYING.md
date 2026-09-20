# Verifying a release

Releases are signed with [Sigstore](https://www.sigstore.dev/) keyless signing.
There is no long-lived signing key: the identity is the GitHub Actions workflow
that built the artifact, and every signature is recorded in the public Rekor
transparency log.

## Verify a downloaded artifact

```bash
pip install sigstore

sigstore verify identity \
  --cert-identity "https://github.com/tusharkarumudi/REPO/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  PACKAGE-X.Y.Z.tar.gz
```

Substitute the real owner, repo and tag. If verification fails, the artifact was
not produced by that workflow at that tag — do not install it.

## Checksums

`SHA256SUMS` is published with each release and is itself signed.

```bash
sha256sum -c SHA256SUMS
```

## SBOM

`sbom.cyclonedx.json` is a CycloneDX software bill of materials for the release,
signed alongside the artifacts. Feed it to your own dependency scanner rather
than trusting this project's assessment of its own supply chain.

## What signing does and does not prove

It proves the artifact came from this repository's release workflow at the stated
tag and has not been altered since. It does not prove the code is correct, safe,
or free of vulnerabilities. Read it.
