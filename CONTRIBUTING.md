# Contributing to Agent44

See the `README.md` for the project overview and setup instructions.

## Development Setup

1. Clone the repository and enter the directory
2. Create a virtual environment: `uv venv .venv && source .venv/bin/activate`
3. Install dependencies: `uv sync`
4. Run the test suite: `uv run pytest -q`
5. Run the linter: `uv run ruff check .`
6. Run the release check: `python release_check.py`

## Coding Guidelines

- Follow the existing code style in the repository
- Run `uv run ruff check .` before committing to ensure lint cleanliness
- Add new synthetic scenarios in the `evaluation/` directory following the existing pattern
- Ensure frozen-file hashes are updated when source files change
- Maintain the deterministic policy engine's fail-closed behavior

## Adding Synthetic Scenarios

1. Add a new scenario to the versioned corpus (`agent44.corpus`)
2. Update the test fixtures as needed
3. Ensure the frozen-file hashes are updated via `python release_check.py`
4. Document the scenario's expected decision and rule behavior

## Release Check

All contributions must pass the full release check:

```
python release_check.py
```

This verifies:
1. `assemble.py` produces no unexpected changes
2. Full `pytest` passes
3. `ruff` output matches the committed baseline
4. All `agent44.*` modules import cleanly
5. Frozen-file hashes remain unchanged

## Questions or Discussion

- Open a discussion on the project's discussion board
- Contact the maintainers directly for complex changes