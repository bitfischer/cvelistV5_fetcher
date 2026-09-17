# Security Policy

cvelistV5_fetcher is a proof-of-concept, maintained on a best-effort basis —
see the [README](README.md) for what that means in practice. That said,
reports about the application itself (not the CVE data it imports) are
welcome.

## Reporting a vulnerability

If you find a security issue in this codebase (not in the upstream CVE data
it fetches), please use GitHub's private reporting instead of opening a
public issue: go to the **Security** tab of this repository and select
**Report a vulnerability**. That opens a private advisory only you and the
maintainer can see, which is the right channel for anything a public issue
would otherwise expose before it's fixed.

If private reporting isn't available for you, a regular
[GitHub issue](../../issues) is fine for lower-severity findings (e.g. an
outdated dependency with no known exploit path).

## Scope

In scope: the FastAPI backend, the web frontend, the Docker image, and the
fetch/ingest pipeline in this repository.

Out of scope: the accuracy or completeness of CVE records themselves — that
data comes from the [CVE Program](https://github.com/CVEProject/cvelistV5)
and should be reported to them directly.

## Supported versions

There's a single moving `main` branch and no long-term support releases.
Fixes land on `main`; there's no backport policy.
