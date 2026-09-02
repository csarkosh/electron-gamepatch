# Adding a patch

A patch is data: `patches/<name>/patch.json` + `README.md`. The engine does the rest. Budget
a few hours the first time; most of it is reading disassembly.

1. **Name the behaviour and find the Chromium function.** Read the Chromium source for the
   behaviour you want to change (https://source.chromium.org). Note the fully qualified
   function name. Check Electron's `patches/chromium/*.patch` — Electron may already alter it.

2. **Get a release and its symbols.** Pick the version the tracked line is on:
   ```sh
   python3 -c "import sys; sys.path.insert(0,'tools'); import gamepatch as g; from pathlib import Path
   g.fetch_upstream('44.1.1','electron-v44.1.1-darwin-arm64.zip',Path('cache'))
   g.fetch_upstream('44.1.1','electron-v44.1.1-darwin-arm64-symbols.zip',Path('cache'))"
   unzip -q cache/v44.1.1/electron-v44.1.1-darwin-arm64.zip -d work/stock
   unzip -q cache/v44.1.1/electron-v44.1.1-darwin-arm64-symbols.zip -d work/symbols
   ```

3. **Find the function.** Breakpad names are demangled C++ without return types:
   ```sh
   grep -n '^FUNC .* PointerLockController::' "work/symbols/breakpad_symbols/Electron Framework/"*/"Electron Framework.sym"
   ```
   Exactly one `FUNC` must match your name; if several do (overloads, template instances),
   qualify the name until one remains — `resolve_symbol` refuses ambiguity.

4. **Disassemble the site.** Address and size come from the `FUNC` line:
   ```sh
   xcrun llvm-objdump -d --start-address=0x903ca3c --stop-address=0x903ca80 \
     "work/stock/Electron.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework"
   ```
   (`--start-address` is ignored if you pass `--macho`; don't.) The `.sym` line records after
   the `FUNC` line map addresses to source lines, which tells you which instructions are the
   `if` you care about.

5. **Choose the smallest rewrite.** Prefer, in order: change a constant (`mov`/`movk` pair on
   arm64), neutralise a branch (`b.cond` → `nop`, `d503201f`), or short-circuit a whole
   function (`mov w0, #<ret>` + `ret`, `00008052 c0035fd6` for `return false`). Never change
   instruction counts; never touch bytes outside the function. Encode with any arm64
   assembler, or take the encoding from an existing instruction in the same binary.

6. **Write `patch.json`.** `expect` = the original bytes at `symbol + offset`; `write` = the
   replacement, same length; `asm` = the instructions `llvm-objdump` should print for
   `write`, as `verify.normalize_disasm` renders them (mnemonic + operands, no comments).

7. **Build, verify, measure.**
   ```sh
   python3 -m unittest discover -s tests -v
   python3 tools/gamepatch.py build --version 44.1.1 --platform darwin-arm64
   python3 tools/verify.py --version 44.1.1 --platform darwin-arm64
   ```
   Then prove the behaviour changed with a probe like `test/probe/` — measured numbers,
   stock vs patched, go in the patch README. A patch without a measurement is not done.

8. **Document.** `patches/<name>/README.md`: what it changes, the upstream source file, the
   bytes, the measurement, what a page must do differently, side effects. Add a row to the
   root README's table. Open a PR.

**When a byte patch is the wrong tool** (you need new logic, a runtime switch, or changes in
several functions), stop: that is a source patch on an Electron fork. `docs/design.md`
describes the cache-only build route.
