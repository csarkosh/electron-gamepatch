# Agents

Start with `.agents/README.md`. To add a patch, follow `.agents/new-patch.md`.
Per-platform facts (binary paths, signing, instruction encoding) are in `.agents/platforms.md`.

Rules that must survive every change:
- Tags and asset names mirror upstream exactly; every release ships `SHASUMS256.txt` and
  pass-through zips for unpatched platforms.
- Sites are `symbol + offset + expect + write`. Never store addresses. Never widen
  `verify.py`'s diff budget to make a build pass.
- Stdlib-only Python; `python3 -m unittest discover -s tests -v` must pass before commit.
