# Contributing to awesome-python-auth

Thank you for your interest in contributing! This guide explains how to get started.

## Development setup

```bash
git clone https://github.com/awesome-lang-auth/awesome-python-auth
cd awesome-python-auth
pip install -e ".[dev]"
python -m pytest tests/ -v   # run the full test suite
```

## Project structure

```
awesome_python_auth/   Library source (Python)
tests/                 pytest test suite
```

## How to contribute

1. **Fork** the repository and create a branch from `main`.
2. Make your changes following the style guide below.
3. Add or update tests to cover your change.
4. Run `python -m pytest tests/ -v` — all tests must pass.
5. Open a **Pull Request** against `main`.

## Style guide

- Python 3.11+ with type annotations — no untyped public APIs.
- No new runtime dependencies without discussion in an issue first.
- Public APIs must be documented with docstrings.
- Existing tests must not be removed or weakened.
- Each commit should be a single logical change.

## Reporting bugs & requesting features

Use the [issue templates](.github/ISSUE_TEMPLATE/) provided. Search for existing issues before opening a new one.

## Security issues

Do **not** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## Code of Conduct

All contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing you agree that your work will be licensed under the [MIT License](LICENSE) that covers this project.
