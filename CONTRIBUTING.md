# Contributing

Thanks for looking. This project is young; the most useful contributions are, in this order:

1. **A failing test vector or a second independent verifier result** for the specification (`spec/`).
   If your implementation disagrees with ours, that is a bug in the spec or in one of us. Open an issue with the vector.
2. **Bypass reports** - a way to forge or alter a receipt, or to make a verifier accept an invalid one (see `SECURITY.md`).
3. Integration examples, docs, bug fixes.

## Ground rules
- Open an issue before a large change. Small fixes: send a pull request.
- Every change to behaviour needs a test. Run the suites listed in `.github/workflows/ci.yml` before you push.
- Sign off your commits (`git commit -s`, Developer Certificate of Origin 1.1). By contributing you agree your work is licensed under Apache-2.0.
- Security issues: do NOT use issues; see `SECURITY.md`.
- Be civil. Be specific. Say what you tested and how.

## Local checks
```
python3 spec/vectors/check_vectors.py
(cd sdk-ts && npm install && npm run build)
(cd verifier_js && npm ci && npm test)
```
