#!/usr/bin/env python3
"""Purpose: test the lock propagation applied to Dependabot branches.

Usage: python3 scripts/test_propagate_lock_versions.py
Last modified: 2026-11-03
"""
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location(
    "propagate", pathlib.Path(__file__).with_name("propagate-lock-versions.py"))
propagate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(propagate)

NEW = {"type": "Transitive", "resolved": "2.0.0", "contentHash": "new",
       "dependencies": {"Added": "1.0.0"}}
ADDED = {"type": "Transitive", "resolved": "1.0.0", "contentHash": "added"}


def stale():
    return {"dependencies": {"net10.0": {
        "Other": {"type": "Transitive", "resolved": "9.0.0", "contentHash": "other"},
        "Pkg": {"type": "CentralTransitive", "requested": "[1.0.0, )", "resolved": "1.0.0",
                "contentHash": "old"},
        "app.ui": {"type": "Project", "dependencies": {"Pkg": "[1.0.0, )", "Other": "[9.0.0, )"}},
    }}}


class ApplyTests(unittest.TestCase):
    def apply(self, document):
        return propagate.apply(document, {"Pkg": NEW}, {"Pkg": NEW, "Added": ADDED})

    def test_updates_the_bumped_package_only(self):
        document = stale()
        self.assertTrue(self.apply(document))
        packages = document["dependencies"]["net10.0"]
        self.assertEqual("2.0.0", packages["Pkg"]["resolved"])
        self.assertEqual("new", packages["Pkg"]["contentHash"])
        self.assertEqual("[2.0.0, )", packages["Pkg"]["requested"])
        self.assertEqual("CentralTransitive", packages["Pkg"]["type"])
        self.assertEqual("9.0.0", packages["Other"]["resolved"])

    def test_updates_the_range_recorded_by_a_project(self):
        document = stale()
        self.apply(document)
        dependencies = document["dependencies"]["net10.0"]["app.ui"]["dependencies"]
        self.assertEqual("[2.0.0, )", dependencies["Pkg"])
        self.assertEqual("[9.0.0, )", dependencies["Other"])

    def test_adds_a_new_transitive_package_in_lock_order(self):
        document = stale()
        self.apply(document)
        names = list(document["dependencies"]["net10.0"])
        self.assertEqual(["Added", "Other", "app.ui", "Pkg"], names)

    def test_leaves_an_unrelated_lock_untouched(self):
        document = {"dependencies": {"net10.0": {
            "Other": {"type": "Transitive", "resolved": "9.0.0", "contentHash": "other"}}}}
        self.assertFalse(self.apply(document))
        self.assertEqual(["Other"], list(document["dependencies"]["net10.0"]))


if __name__ == "__main__":
    unittest.main()
