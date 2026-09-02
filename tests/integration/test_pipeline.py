"""Build the pinned Electron end to end and check every property the release contract depends on.

Runs for every patched platform (darwin-arm64 and win32-x64). PE has no signature and cannot be
launched on the macOS gate runner, so those two checks are darwin-only; win32-x64's launch and
behaviour proof is the Windows probe leg.

Downloads ~500 MB into cache/ on first run (subsequent runs hit the cache); takes 3–6 minutes.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import gamepatch  # noqa: E402
import verify  # noqa: E402

PIN = os.environ.get("GAMEPATCH_PIN", "44.1.1")
CACHE, WORK, DIST = ROOT / "cache", ROOT / "work", ROOT / "dist"


def zip_entries(path: Path) -> set[tuple[str, str]]:
    """(perms, name) for every entry in `path`, from `zipinfo`'s long listing.

    Names alone (`unzip -Z1`) would let a symlink silently become a regular file, or a mode
    change go unnoticed, and the comparison would still pass. `zipinfo`/`unzip -Z` lines look
    like `lrwxr-xr-x  3.0 unx  35 bx stor 80-Jan-01 00:00 <name>`; the header (`Archive: ...`,
    `Zip file size: ...`) and trailer (`583 files, ... compressed:`) lines don't start with a
    permission string, so filtering on that first character sorts them out. Names can contain
    spaces (`Electron Framework`), so the name is taken as everything after the fixed 8-field
    prefix, not a plain `.split()`.
    """
    lines = subprocess.run(["unzip", "-Z", str(path)], check=True, text=True, capture_output=True).stdout.splitlines()
    entries: set[tuple[str, str]] = set()
    for line in lines:
        if not line or line[0] not in "-dlpsbc":
            continue
        parts = line.split(maxsplit=8)
        if len(parts) != 9:
            continue
        perms, name = parts[0], parts[8]
        entries.add((perms, name))
    return entries


class PipelineChecks:
    """The per-platform half of the suite. A mixin, not a TestCase, so these run once per
    concrete platform subclass below and never as an abstract, platform-less case."""

    PLATFORM = ""
    FMT = "macho"
    #: upstream's zip for this platform contains at least one symlink entry (true of the macOS
    #: bundles, false of the Windows tree), which is the fixture sanity check for the layout test.
    HAS_SYMLINKS = True
    #: How faithfully our re-zip can reproduce upstream's entry metadata. Upstream's macOS zips
    #: are made on Unix by the same `zip` we re-zip with, so every (perms, name) pair must match
    #: exactly. Upstream's win32 zip is made on Windows: its entries carry DOS attributes rather
    #: than Unix modes (`zipinfo` renders its electron.exe as `-rwx---`) and it stores no
    #: directory entries at all — neither is reproducible from the macOS build runner. For PE we
    #: therefore compare file entries by name and type, which is what an extractor acts on; the
    #: directory entries ours adds are the directories any extractor creates anyway.
    EXACT_MODES = True

    @classmethod
    def setUpClass(cls):
        DIST.mkdir(parents=True, exist_ok=True)
        built_zip = DIST / f"electron-v{PIN}-{cls.PLATFORM}.zip"
        stock, patched = WORK / cls.PLATFORM / "stock", WORK / cls.PLATFORM / "patched"
        # The gate's build step produced the artifact that actually ships (uploaded by build,
        # downloaded by publish, released as-is); this suite must examine that artifact, not a
        # rebuild of its own, or a difference introduced only by rebuilding would go uncaught.
        if built_zip.exists() and stock.is_dir() and patched.is_dir():
            cls.out_zip = built_zip
        else:
            cls.out_zip = gamepatch.build(PIN, cls.PLATFORM, ROOT / "patches", CACHE, WORK, DIST)
        cls.record = json.loads((DIST / f"electron-v{PIN}-{cls.PLATFORM}.patches.json").read_text())
        cls.stock_zip = CACHE / f"v{PIN}" / f"electron-v{PIN}-{cls.PLATFORM}.zip"

    def test_record_declares_every_patch_targeting_the_platform(self):
        expected = sorted(p["name"] for p in gamepatch.load_patches(ROOT / "patches") if self.PLATFORM in p["targets"])
        self.assertEqual(sorted(p["name"] for p in self.record["patches"]), expected)
        for patch in self.record["patches"]:
            self.assertTrue(patch["sites"], f"{patch['name']} applied no sites")

    def test_zip_layout_matches_upstream(self):
        """Same entries, same type and mode, as upstream's zip: the consumer's extractor must see an
        identical tree. Comparing names alone would miss a symlink rewritten as a regular file or a
        mode change; comparing (perms, name) pairs catches both."""
        ours, theirs = zip_entries(self.out_zip), zip_entries(self.stock_zip)
        self.assertEqual(any(perms.startswith("l") for perms, _ in theirs), self.HAS_SYMLINKS,
                         f"fixture sanity: upstream's {self.PLATFORM} zip symlink entries are not as expected")
        if self.EXACT_MODES:
            self.assertEqual(ours, theirs)
            return
        self.assertEqual({n for _, n in theirs if n.endswith("/")}, set(),
                         "upstream's win32 zip now stores directory entries; compare them too")
        files = lambda entries: {(perms[0], name) for perms, name in entries if not name.endswith("/")}  # noqa: E731
        self.assertEqual(files(ours), files(theirs))

    def test_patched_binary_passes_verify(self):
        for patch in self.record["patches"]:
            rel = patch["binary"]
            verify.check_sites(WORK / self.PLATFORM / "stock" / rel,
                               WORK / self.PLATFORM / "patched" / rel, patch["sites"], fmt=self.FMT)

    def test_shasums_lists_the_built_zip_with_its_real_hash(self):
        entries = gamepatch.parse_shasums(gamepatch.shasums(DIST))
        self.assertEqual(entries[self.out_zip.name], gamepatch.sha256_file(self.out_zip))

    def test_notes_name_the_patch_and_the_consumer_config(self):
        notes = gamepatch.notes(PIN, ROOT / "patches", DIST)
        for patch in self.record["patches"]:
            self.assertIn(patch["name"], notes)
        self.assertIn("electron_use_remote_checksums=1", notes)


class PipelineDarwinArm64(PipelineChecks, unittest.TestCase):
    PLATFORM = "darwin-arm64"

    def test_signature_valid(self):
        for patch in self.record["patches"]:
            verify.signature_valid(WORK / self.PLATFORM / "patched" / patch["binary"])

    def test_launches_and_reports_version(self):
        verify.launch_smoke(WORK / self.PLATFORM / "patched" / "Electron.app", PIN)


class PipelineWin32X64(PipelineChecks, unittest.TestCase):
    """PE has no signature to verify and cannot be launched on the macOS gate runner: the launch
    and behaviour proof for win32-x64 is the Windows probe leg (`.github/actions/probe-windows`)."""

    PLATFORM = "win32-x64"
    FMT = "pe"
    HAS_SYMLINKS = False
    EXACT_MODES = False


class UpstreamAssets(unittest.TestCase):
    def test_upstream_publishes_every_platform_zip_we_expect(self):
        """These are the platform zips we expect upstream to publish; if the names change, publish would silently ship fewer platforms."""
        names = gamepatch.upstream_asset_names(gamepatch.upstream_release(PIN), PIN)
        for platform in ("darwin-arm64", "darwin-x64", "win32-x64", "linux-x64"):
            self.assertIn(f"electron-v{PIN}-{platform}.zip", names)
        shasums = gamepatch.upstream_shasums(PIN, CACHE)
        for name in names:
            self.assertIn(name, shasums, f"{name} is a release asset but not in upstream SHASUMS256.txt")


if __name__ == "__main__":
    unittest.main()
