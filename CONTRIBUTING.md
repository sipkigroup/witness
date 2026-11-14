# Contributing

Thanks for looking. This project is young; the most useful contributions are, in this order:

1. **A failing test vector or a second independent verifier result** for the specification (`spec/`).
   If your implementation disagrees with ours, that is a bug in the spec or in one of us. Open an issue with the vector.
2. **Bypass reports** - a way to forge or alter a receipt, or to make a verifier accept an invalid one (see `SECURITY.md`).
3. Integration examples, docs, bug fixes.

## Ground rules
- Open an issue before a large change. Small fixes: send a pull request.
- Every change to behaviour needs a test. Run the suites listed in `.github/workflows/ci.yml` before you push.
- Sign off every commit (`git commit -s`), see "Developer Certificate of Origin" below. By contributing you agree your work is licensed under Apache-2.0.
- Security issues: do NOT use issues; see `SECURITY.md`.
- Be civil. Be specific. Say what you tested and how.

## Local checks
```
python3 spec/vectors/check_vectors.py
(cd sdk-ts && npm install && npm run build)
(cd verifier_js && npm ci && npm test)
```

## Developer Certificate of Origin

Every commit in a pull request must end with a line

```
Signed-off-by: Your Name <the e-mail of the commit author>
```

`git commit -s` adds it. With it you certify the Developer Certificate of Origin 1.1 (the file `DCO` in this
repository, text of https://developercertificate.org/): you wrote the change, or you have the right to submit it under
this project's license. Use your real name or a name you are known by; no anonymous contributions.

If you used an AI tool to write part of the change, you may still sign off, but you remain responsible for the change:
check that the tool's terms let you contribute its output, and say in the pull request which parts it wrote.

The `dco` check (`.github/workflows/dco.yml`) fails a pull request with a commit that has no such line.
Fix it with `git rebase --signoff <base>` (or `git commit --amend -s` for the last commit) and push again.
