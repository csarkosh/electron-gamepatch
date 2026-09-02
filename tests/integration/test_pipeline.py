"""Build the pinned Electron end to end and check every property the release contract depends on.

Downloads ~260 MB into cache/ on first run (subsequent runs hit the cache); takes 2–4 minutes.
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
PLATFORM = "darwin-arm64"
CACHE, WORK, DIST = ROOT / "cache", ROOT / "work", ROOT / "dist"


def zip_entries(path: Path) -> set[str]:
    return set(subprocess.run(["unzip", "-Z1", str(path)], check=True, text=True, capture_output=True).stdout.split("\n")) - {""}


class Pipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        DIST.mkdir(parents=True, exist_ok=True)
        cls.out_zip = gamepatch.build(PIN, PLATFORM, ROOT / "patches", CACHE, WORK, DIST)
        cls.record = json.loads((DIST / f"electron-v{PIN}-{PLATFORM}.patches.json").read_text())
        cls.stock_zip = CACHE / f"v{PIN}" / f"electron-v{PIN}-{PLATFORM}.zip"

    def test_record_declares_every_patch_targeting_the_platform(self):
        expected = sorted(p["name"] for p in gamepatch.load_patches(ROOT / "patches") if PLATFORM in p["targets"])
        self.assertEqual(sorted(p["name"] for p in self.record["patches"]), expected)
        for patch in self.record["patches"]:
            self.assertTrue(patch["sites"], f"{patch['name']} applied no sites")

    def test_zip_layout_matches_upstream(self):
        """Same entries as upstream's zip: the consumer's extractor must see an identical tree (symlinks included)."""
        self.assertEqual(zip_entries(self.out_zip), zip_entries(self.stock_zip))

    def test_patched_binary_passes_verify(self):
        for patch in self.record["patches"]:
            rel = patch["binary"]
            verify.check_sites(WORK / PLATFORM / "stock" / rel, WORK / PLATFORM / "patched" / rel, patch["sites"])

    def test_launches_and_reports_version(self):
        verify.launch_smoke(WORK / PLATFORM / "patched" / "Electron.app", PIN)

    def test_shasums_lists_the_built_zip_with_its_real_hash(self):
        entries = gamepatch.parse_shasums(gamepatch.shasums(DIST))
        self.assertEqual(entries[self.out_zip.name], gamepatch.sha256_file(self.out_zip))

    def test_notes_name_the_patch_and_the_consumer_config(self):
        notes = gamepatch.notes(PIN, ROOT / "patches", DIST)
        for patch in self.record["patches"]:
            self.assertIn(patch["name"], notes)
        self.assertIn("electron_use_remote_checksums=1", notes)

    def test_upstream_publishes_every_passthrough_platform_we_expect(self):
        """Pass-through relies on upstream's asset names; if they change, publish would silently ship fewer platforms."""
        names = gamepatch.upstream_asset_names(gamepatch.upstream_release(PIN), PIN)
        for platform in ("darwin-arm64", "darwin-x64", "win32-x64", "linux-x64"):
            self.assertIn(f"electron-v{PIN}-{platform}.zip", names)
        shasums = gamepatch.upstream_shasums(PIN, CACHE)
        for name in names:
            self.assertIn(name, shasums, f"{name} is a release asset but not in upstream SHASUMS256.txt")


if __name__ == "__main__":
    unittest.main()
