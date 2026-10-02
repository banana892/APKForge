# Validation Environment

Corpus validation, security validation and the Phase B acceptance evidence are produced in
one locked Python environment. Every pinned package version is recorded, so a corpus result
can be matched to the exact environment that produced it.

## What is locked

| file | purpose |
|---|---|
| `requirements/validation.in` | Exact `==` pins for every package in the reference environment (the `pip freeze` of the venv used for the Phase B regression reconciliation, minus the editable `apkforge` line). |
| `requirements/validation.lock` | `validation.in` compiled by `uv pip compile --generate-hashes`: the same pins plus SHA-256 hashes for every distribution. **This is the lock.** |

The lock covers the **complete** dependency set: runtime dependencies (`androguard`,
`cryptography`, `pydantic`, …), their transitive dependencies, and the dev tools used for
validation (`pytest`, `ruff`, `mypy`). Compiling `validation.in` resolves no package beyond
the ones it lists, so the set is closed.

Reference values:

| item | value |
|---|---|
| Python | **3.14.7** (CPython) |
| `cryptography` | 50.0.1 (bundles OpenSSL 4.0.2) |
| `androguard` | 4.1.4 |
| `asn1crypto` | 1.5.1 |
| platform used for the reference | Fedora 44, x86_64 |

The lock exists for **reproducibility**. Nothing is pinned because it is believed to fix or
cause a particular behaviour.

`.python-version` says `3.11`, which is the project's minimum supported version for
development. Validation uses 3.14.7, so the commands below name the interpreter explicitly.

## Recreate the environment

Requires [`uv`](https://docs.astral.sh/uv/) (the reference used uv 0.12.22).

```bash
# 1. Fresh venv on the reference interpreter (uv downloads it if absent)
uv venv --python 3.14.7 .venv-validation

# 2. Install exactly the locked set; hashes are verified, nothing else is installed
uv pip sync --python .venv-validation/bin/python --require-hashes requirements/validation.lock

# 3. Install APKForge itself, editable, without touching the locked dependencies
uv pip install --python .venv-validation/bin/python --no-deps -e .

# 4. Confirm
.venv-validation/bin/python -c "import cryptography, androguard; \
from cryptography.hazmat.backends.openssl.backend import backend; \
print(cryptography.__version__, backend.openssl_version_text())"
```

Run validation with that interpreter:

```bash
.venv-validation/bin/python -m pytest -q
.venv-validation/bin/python -m ruff check src
.venv-validation/bin/python -m mypy src/apkforge
.venv-validation/bin/python tests/corpus_runner.py
```

`uv pip sync` removes anything not in the lock, which is why step 3 comes after it.

## Environment identity in corpus results

`tests/corpus_runner.py` writes `meta.environment` into every new `tests/corpus_results.json`:
Python version and executable, platform, `cryptography` version and its bundled OpenSSL,
`androguard`, `asn1crypto` and `pydantic` versions, the lock path, and the lock's SHA-256.
A result whose `lock_sha256` matches `sha256sum requirements/validation.lock` was produced
in this environment; a result without `meta.environment` predates the lock.

## Updating the lock

Change the pins in `requirements/validation.in` deliberately, then regenerate:

```bash
uv pip compile requirements/validation.in --generate-hashes --python-version 3.14 \
  --python-platform x86_64-unknown-linux-gnu -o requirements/validation.lock
```

Recreate `.venv-validation` from the new lock and re-run the full validation set. Any
corpus artifact produced afterwards carries the new `lock_sha256`, so results from the two
environments can be told apart.
