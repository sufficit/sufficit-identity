#!/usr/bin/env python3
"""Purpose: carry the packages a Dependabot PR bumped into every stale packages.lock.json.

Dependabot regenerates only the lock of the project that references a package
directly. Projects depending on that one keep the old version, and
`dotnet restore --locked-mode` refuses them with NU1004. Editing just those
packages keeps every other pin intact; `--force-evaluate` would also float
unrelated packages that use a version range.

Reads and writes JSON only, so it is safe to run over an untrusted checkout.

Usage: propagate-lock-versions.py <base-ref>   (run from the repository root)
Last modified: 2026-11-03
"""
import json
import subprocess
import sys


def git(*args):
    return subprocess.check_output(["git", *args], text=True)


def bumped_packages(base):
    """Packages whose resolved version differs from base in any lock the PR changed,
    and every package of those locks, which is where a new transitive package comes from."""
    changed = {}
    known = {}
    for path in git("diff", "--name-only", base, "HEAD", "--", "*packages.lock.json").split():
        new = json.loads(git("show", f"HEAD:{path}").lstrip("﻿"))
        old = json.loads(git("show", f"{base}:{path}").lstrip("﻿"))
        for framework, packages in new["dependencies"].items():
            previous = old["dependencies"].get(framework, {})
            for name, entry in packages.items():
                if entry.get("type") == "Project" or "resolved" not in entry:
                    continue
                known[name] = entry
                if name in previous and previous[name].get("resolved") != entry["resolved"]:
                    changed[name] = entry
    return changed, known


TYPE_ORDER = {"Direct": 0, "Transitive": 1, "Project": 2, "CentralTransitive": 3}


def add_missing_dependencies(packages, entry, known):
    """A bumped package may depend on one this project never had; the lock must list it."""
    added = False
    for name in entry.get("dependencies", {}):
        if name not in packages and name in known:
            packages[name] = dict(known[name])
            add_missing_dependencies(packages, packages[name], known)
            added = True
    return added


def apply(document, changed, known):
    touched = False
    for framework, packages in document["dependencies"].items():
        grew = False
        for name, entry in list(packages.items()):
            if entry.get("type") == "Project":
                # A project entry records the range its own dependencies ask for.
                for dependency in entry.get("dependencies", {}):
                    if dependency in changed:
                        wanted = f"[{changed[dependency]['resolved']}, )"
                        if entry["dependencies"][dependency] != wanted:
                            entry["dependencies"][dependency] = wanted
                            touched = True
            source = changed.get(name)
            if source is None or entry.get("resolved") == source["resolved"]:
                continue
            entry["resolved"] = source["resolved"]
            entry["contentHash"] = source["contentHash"]
            if "requested" in entry:
                entry["requested"] = source.get("requested", f"[{source['resolved']}, )")
            if "dependencies" in source:
                entry["dependencies"] = source["dependencies"]
            grew = add_missing_dependencies(packages, entry, known) or grew
            touched = True
        if grew:
            document["dependencies"][framework] = dict(sorted(
                packages.items(),
                key=lambda item: (TYPE_ORDER.get(item[1].get("type"), 9), item[0].lower())))
    return touched


def main():
    changed, known = bumped_packages(sys.argv[1])
    print("bumped:", {name: entry["resolved"] for name, entry in sorted(changed.items())})
    for path in git("ls-files", "*packages.lock.json").split():
        with open(path, encoding="utf-8-sig") as stream:
            raw = stream.read()
        document = json.loads(raw)
        if apply(document, changed, known):
            with open(path, "w", encoding="utf-8") as stream:
                stream.write(json.dumps(document, indent=2, ensure_ascii=False))
                if raw.endswith("\n"):
                    stream.write("\n")
            print("updated", path)


if __name__ == "__main__":
    main()
