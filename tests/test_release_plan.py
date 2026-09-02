import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import release_plan  # noqa: E402

UP = ["v44.1.1", "v43.5.1", "v44.1.0", "v42.11.1", "v45.0.0-beta.3", "v44.0.0", "v44.0.1"]


class Plan(unittest.TestCase):
    def test_first_run_builds_only_the_latest_on_the_highest_major(self):
        self.assertEqual(release_plan.versions_to_build(UP, []), ["44.1.1"])

    def test_builds_everything_newer_than_ours_on_the_major(self):
        self.assertEqual(release_plan.versions_to_build(UP, ["v44.0.1"]), ["44.1.0", "44.1.1"])

    def test_nothing_when_current(self):
        self.assertEqual(release_plan.versions_to_build(UP, ["v44.1.1"]), [])

    def test_prereleases_are_never_tracked(self):
        self.assertNotIn("45.0.0-beta.3", release_plan.versions_to_build(UP, []))

    def test_new_major_upstream_moves_the_line(self):
        self.assertEqual(release_plan.versions_to_build(UP + ["v45.0.0"], ["v44.1.1"]), ["45.0.0"])

    def test_parse_and_sort(self):
        self.assertEqual(release_plan.parse_version("v44.10.2"), (44, 10, 2))
        self.assertLess(release_plan.parse_version("v44.9.9"), release_plan.parse_version("v44.10.0"))
