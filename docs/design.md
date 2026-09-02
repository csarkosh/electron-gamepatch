# electron-gamepatch — design

**Status: approved 2026-09-01.** A new public repository, `github.com/csarkosh/electron-gamepatch`,
that republishes official Electron releases with small binary patches that remove
game-hostile browser behaviour. First patch: the pointer-lock Esc eject
(`docs/research/2026-08-25-pointer-lock-cooldown.md`, "Binary-patch spike"). The game's desktop
shell consumes it exactly as it would consume upstream Electron.

## Goals

1. **Plug-and-play.** A consumer adds two lines to `.npmrc` and `npm install electron@X.Y.Z`
   pulls our bytes; `electron-builder` and everything downstream are unaffected.
2. **Free to run.** Every step runs on GitHub-hosted runners that are free for public repos.
   No Chromium checkout, no compile, no paid runners.
3. **Verifiable.** Every artifact is byte-identical to the upstream release except the
   documented patch bytes. Anyone can `cmp` it.
4. **A series, not a one-off.** Adding a second patch means adding data and a README, not a
   pipeline.

## Non-goals

- A source fork of Electron/Chromium. That is the escalation path for changes a byte patch
  cannot express (see the research doc's route B); it is documented, not built.
- Patches for platforms we have not measured. v1 ships **darwin-arm64** only.
- The game's desktop shell itself. That is the next task in the `fps` repo.

## The release contract

This is the load-bearing part; everything else serves it.

- **Tags mirror upstream exactly**: our `v44.1.1` republishes Electron `v44.1.1`.
  `@electron/get`'s default `customDir` is `v{{ version }}`, so consumers need no
  `ELECTRON_CUSTOM_DIR`.
- **Assets are named exactly as upstream**: `electron-v44.1.1-darwin-arm64.zip`.
- **Every release publishes its own `SHASUMS256.txt`** in upstream's format
  (`<sha256> *<filename>` per line). The `electron` npm package verifies downloads against a
  *bundled* `checksums.json` by default, which would reject our bytes; consumers set
  `electron_use_remote_checksums=1`, which makes `@electron/get` fetch `SHASUMS256.txt` from
  the mirror instead.
- **Pass-through for unpatched platforms.** Each release also re-uploads upstream's other
  `electron-*` zips unmodified (darwin-x64, mas-*, win32-*, linux-*; ~1 GB per release, within
  GitHub's per-asset 2 GB limit). Without this, pointing `electron_mirror` at us breaks
  `npm install` on every machine we have no patch for. The README states the rule:
  *patched where a patch exists, byte-identical to upstream everywhere else.*
- **Tracked line: latest stable major** (44.x today). Every patch release on it is republished.
  Older majors are not tracked; a manual dispatch can backfill any version.

Consumer configuration, verbatim:

```ini
# .npmrc
electron_mirror=https://github.com/csarkosh/electron-gamepatch/releases/download/
electron_use_remote_checksums=1
```

## Repository layout

```
patches/
  pointerlock-noeject/
    patch.json          declarative: per platform-arch, the symbol, expected bytes, replacement
    README.md           what it changes, why, the upstream source it patches, measured effect
tools/
  gamepatch.py          the engine (Python 3, stdlib only)
  verify.py             post-patch disassembly assertion + launch smoke
test/probe/             the spike's probe app + run.sh: measures relock time with a real Esc
.github/workflows/
  release.yml           cron + manual dispatch → build → verify → GitHub release
.agents/                agent onboarding for future patches (see below)
AGENTS.md               points at .agents/
README.md               consumer setup, the contract above, patch list
LICENSE                 MIT (Electron's own licence files ship inside every zip unchanged)
```

## Patch specification format

One `patch.json` per patch. Data, not code:

```json
{
  "name": "pointerlock-noeject",
  "summary": "Esc never ejects pointer lock; the page owns Esc.",
  "targets": {
    "darwin-arm64": {
      "binary": "Electron.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework",
      "sites": [
        {
          "symbol": "PointerLockController::HandleUserPressedEscape()",
          "offset": 0,
          "expect": "f44fbea9fd7b01a9",
          "write":  "00008052c0035fd6",
          "asm":    "mov w0, #0 ; ret"
        }
      ]
    }
  }
}
```

- `symbol` is matched exactly against the `FUNC` lines of the release's Breakpad `.sym`
  file; the engine resolves it to an address per release, so **no offsets are stored**.
- `offset` is relative to the function start (0 = prologue).
- `expect` is asserted before writing. A compiler change in a new Electron alters the
  prologue → the assertion fails → the run is red and nothing is published. That is the
  designed failure mode; a human re-derives the bytes.
- `asm` is documentation and the input to `verify.py`'s disassembly check.
- Platforms not listed in `targets` are pass-through.

## The engine (`tools/gamepatch.py`)

Stdlib only (`urllib`, `zipfile`, `hashlib`, `subprocess`, `json`); runs on the runner and on
any developer machine. For a given version:

1. Download `electron-v<ver>-<platform>.zip` and `electron-v<ver>-<platform>-symbols.zip`
   from `github.com/electron/electron/releases`, verifying each against upstream's
   `SHASUMS256.txt`. Cache by filename.
2. Parse `Electron Framework.sym`: assert its `MODULE` UUID equals the binary's (`dwarfdump
   --uuid`), then build `{symbol → (address, size)}` from `FUNC` lines. `__TEXT` is at
   `vmaddr 0`, so address == file offset; the engine asserts this from `otool -l` rather than
   assuming it.
3. For each site: read `len(expect)` bytes at `address + offset`; assert equal; write.
4. Re-sign only the binaries the patch modified: `codesign --force --sign - <binary>` then
   `codesign --verify --strict <binary>`. No `--deep`: upstream is linker-signed with no
   bundle seals, and a deep re-sign would add `_CodeSignature/CodeResources` entries the
   upstream zip does not have. Signing happens on a copy in a scratch directory outside the
   bundle tree, then the signed bytes are copied back in place: codesign auto-detects a
   framework's designated main executable from its neighbours and seals the whole bundle
   even without `--deep`, so a plain, bundle-free path is required to get a bare embedded
   signature on the binary alone.
5. Re-zip with the same top-level layout as upstream (`Electron.app`, `LICENSE`,
   `LICENSES.chromium.html`, `version`), preserving symlinks and modes (`zip -ry`).
6. Emit `SHASUMS256.txt` covering every asset in the release (patched and pass-through).

## Verification (`tools/verify.py`)

Runs after the engine, before publishing:

1. **Disassembly**: `llvm-objdump -d --start-address --stop-address` over each site; assert
   the instructions match `asm`.
2. **Diff budget**: byte-compare patched vs upstream binary; assert the *only* differing
   ranges are the declared sites.
3. **Launch smoke**: `Electron.app/Contents/MacOS/Electron --version` prints `v<ver>`.
4. **Functional probe** (`test/probe/run.sh`): lock → real Esc via `osascript` → relock;
   assert the page saw `keydown Escape` while locked and relocked on the first attempt.
   A blocking gate, locally and in CI, run with the stock build as a control so a runner
   that swallows keystrokes cannot produce a false pass. Whether GitHub's `macos-14` image
   grants `osascript` the Accessibility permission this needs is unknown until the first
   run; if it refuses, the decision (self-hosted runner label for this step, or a required
   local pre-release step) is the owner's — the gate is not weakened.

## Integration suite — the CI/CD gate (added 2026-09-01)

Unit tests cover the pure functions; an integration suite in `tests/integration/` covers the
pipeline and the release contract, and runs as a **gate** on every push and pull request
(`ci.yml`) and inside the release workflow before anything is published — both through one
composite action (`.github/actions/gate`) so they cannot drift.

1. **Pipeline properties** against a pinned real Electron (`GAMEPATCH_PIN`, 44.1.1 today):
   the build record declares every patch targeting the platform; the patched zip has exactly
   upstream's entry list (symlinks included); `verify.py` passes; the binary launches;
   `SHASUMS256.txt` carries the built zip's real hash; release notes name the patch and the
   consumer config; upstream still publishes every pass-through platform we promise, and
   every such asset is in upstream's own `SHASUMS256.txt`.
2. **Consumer contract**: the real `electron` npm package's `install.js`, driven exactly as a
   consumer's `.npmrc` would drive it (`npm_config_electron_mirror`,
   `npm_config_electron_use_remote_checksums`), against a local HTTP mirror serving `dist/`
   in the release layout. Asserts the installed framework's hash equals the patched one, and
   — with a corrupted `SHASUMS256.txt` — that the install is refused, proving checksum
   enforcement is live and not silently bypassed.
3. **Behaviour**: the probe, as above.

A change to the engine, the release layout, the patch data, or the tracked Electron that
breaks any of these turns the gate red before it can reach a release.

## Workflow (`.github/workflows/release.yml`)

- Triggers: daily cron; `workflow_dispatch` with an optional `version` input.
- Job `plan` (ubuntu): list upstream releases on the tracked major, subtract our tags, emit
  the list to build (or the dispatched version).
- Job `build` (matrix over versions, `macos-14`, free for public repos; needed for
  `codesign`, `llvm-objdump`, `dwarfdump`): the `gate` action (unit → engine → verify →
  integration suite → probe) → upload artifacts.
- Job `publish`: create the release `v<ver>` with all assets and `SHASUMS256.txt`, release
  notes generated from the patch READMEs plus the upstream release link. Idempotent: an
  existing tag is skipped, never overwritten.
- No secrets beyond `GITHUB_TOKEN`.

## `.agents/` — onboarding for the next patch

The owner intends a series of patches. `.agents/` exists so a future agent (or human) can add
one without rediscovering the method:

- `.agents/README.md` — how the repo works, the release contract, what must never change
  (tag/asset naming, SHASUMS, pass-through).
- `.agents/new-patch.md` — the runbook, distilled from the spike: pick the Chromium function
  from source → find it in the release's `.sym` → disassemble the site → choose the smallest
  instruction rewrite → write `patch.json` with `expect`/`write`/`asm` → run engine + verify +
  probe locally → open a PR with the measured effect in the patch README.
- `.agents/platforms.md` — per-platform notes: where the framework binary lives, signing
  requirements, how the constant is encoded on arm64 vs x64, which tools exist on each runner.
- `AGENTS.md` at the root points here; `CLAUDE.md` is a one-line pointer to `AGENTS.md`.

## Testing the pipeline itself

- Engine unit tests (`python -m unittest`): `.sym` parsing on a fixture excerpt; the
  expect/write assertion on a synthetic binary; `SHASUMS256.txt` formatting.
- The first end-to-end run is a manual dispatch for `v44.1.1`; its output is verified locally
  with `test/probe/run.sh` and with the `fps` game (`tools/electron-spike/run-game.sh` in the
  `fps` repo) before the cron is enabled.

## Open questions

None blocking. Two decisions deferred to when they matter:

- Whether the tracked line should follow the `fps` desktop shell's pinned Electron rather than
  "latest stable major" once the shell exists.
- Windows/Linux patches: the engine and contract support them; each needs its own
  disassembly spike to fill `targets`.
