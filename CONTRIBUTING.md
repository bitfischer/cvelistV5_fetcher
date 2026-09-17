# Contributing

This is a personal proof-of-concept project, not a production tool — see the
[README](README.md#what-is-this) for what it is and isn't meant to be. Issues
and small pull requests are welcome; just keep expectations calibrated to
that scope.

## Getting set up

```sh
make install   # creates .venv, installs the app + dev dependencies
make test      # runs the test suite
make dev       # runs the app locally with auto-reload
```

See the [README](README.md) for fetching CVE data and running via Docker.

## Before opening a pull request

- Run `make test` and make sure it passes.
- If you touched a runtime dependency, regenerate the SBOM with `make sbom`
  and include the updated `web/sbom.json` in your PR.
- Keep changes focused — a bug fix doesn't need an unrelated refactor riding
  along with it.
- Follow the existing code style (the codebase has no linter configured
  beyond what's already there; match what you see nearby).

## Reporting bugs

Open a [GitHub issue](../../issues) with what you expected, what happened
instead, and how to reproduce it. For security issues, see
[SECURITY.md](SECURITY.md) instead of opening a public issue.
