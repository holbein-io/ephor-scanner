# Contributing to Ephor Scanner

Contributions are welcome and appreciated. This document explains how to get involved.

## Contributor License Agreement

Before we can accept your first pull request, you must sign our [Contributor License Agreement](CLA.md). The CLA is based on the Apache Software Foundation Individual CLA and grants Holbein the right to distribute your contributions.

When you open a pull request, a GitHub Action will check whether you have signed the CLA. If not, it will post a comment with instructions. You sign by adding a comment to the PR:

```
I have read the CLA Document and I hereby sign the CLA
```

You only need to sign once. All future contributions across Holbein repositories are covered.

## Getting Started

1. Fork the repository
2. Create a feature branch from `main` (`feature/my-change` or `fix/the-bug`)
3. Make your changes
4. Run the test suite (see below)
5. Commit using the conventional commit format
6. Open a pull request against `main`

## Development Setup

Prerequisites: Go 1.25+, Make.

```bash
# Build
make build

# Run
./bin/ephor-scanner
```

See the [README](README.md) for full setup details including environment variables.

## Running Tests

```bash
# Unit tests
make test

# Integration tests (requires Trivy binary and network access)
make test-integration

# Lint
make lint

# Format
make fmt
```

Please ensure all tests pass and linting is clean before submitting a pull request.

## Commit Messages

Use the [conventional commit](https://www.conventionalcommits.org/) format:

```
type(scope): description
```

Examples:

```
feat(discovery): add support for ReplicaSet workload type
fix(scanner): handle Trivy timeout for large images
docs: update Helm values table
```

Common types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`.

## Pull Request Guidelines

- Keep PRs focused on a single change
- Add or update tests for new functionality
- Update documentation if behaviour changes
- Fill in the PR description explaining what and why
- Link related issues when applicable

## Reporting Issues

Use GitHub Issues to report bugs or request features. When reporting a bug, include:

- Steps to reproduce
- Expected vs actual behaviour
- Scanner version (`ephor-scanner --version` or commit hash)
- Kubernetes and Trivy versions
- Relevant logs

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Run `make lint` before submitting
- Write clear, self-documenting code; add comments only where the logic is not obvious

## License

By contributing to Ephor Scanner, you agree that your contributions will be licensed under the [GNU Affero General Public License v3.0](LICENSE).
