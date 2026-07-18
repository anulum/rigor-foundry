# Fuzzing

RigorFoundry parses untrusted, content-addressed audit records — reports,
candidates, review ledgers, and policies — that may arrive from other tools or
adopters. Every parser is contractually **fail-closed**: hostile or malformed
input must raise `ValueError`, never crash with an unexpected exception or hang.
Coverage-guided fuzzing verifies that contract continuously.

## Harness

The `fuzz/` directory holds [Atheris](https://github.com/google/atheris)
coverage-guided fuzz targets, one per untrusted-input parser:

| Target | Parser under test |
| --- | --- |
| `fuzz/fuzz_audit_report.py` | `AuditReport.from_dict` |
| `fuzz/fuzz_candidate.py` | `Candidate.from_dict` |
| `fuzz/fuzz_audit_policy.py` | `AuditPolicy.from_json` |
| `fuzz/fuzz_review_record.py` | `ReviewRecord.from_dict` |

Each target feeds fuzzer-derived bytes across the JSON boundary through the
shared helpers in `fuzz/_record_fuzz.py`. The helpers tolerate only the
contractual failure modes — `ValueError` (its fail-closed contract, of which
`UnicodeDecodeError` and `json.JSONDecodeError` are subclasses) and
`RecursionError` (CPython's bounded response to deeply nested input). Any other
exception propagates so the fuzzer records it as a genuine robustness finding.

## Running locally

Install the hash-locked fuzzing environment (Atheris ships wheels for CPython
3.12 and newer) and run a target for a bounded time:

```bash
python -m pip install --require-hashes -r requirements/fuzz.txt
python -m pip install --no-build-isolation --no-deps .
python fuzz/fuzz_audit_report.py -max_total_time=60
```

A crash writes a reproducer file to the working directory; replay it by passing
the file as an argument.

## Continuous integration

The `Fuzz` workflow (`.github/workflows/fuzz.yml`) runs every target for a
bounded interval on each pull request, on `main`, and on a weekly schedule,
failing the job on any crash. The targets are not `pytest` tests and are not
collected by the suite; they exercise the parsers as adversarial input handlers
rather than as behavioural unit tests.
