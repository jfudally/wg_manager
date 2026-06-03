#!/usr/bin/env python3
"""Extract a versioned section from CHANGELOG.md (Phase 2f cycle 2).

The release workflow tags an image with ``v<X.Y.Z>`` and creates a
GitHub release whose body is the matching ``## [vX.Y.Z]`` section of
``CHANGELOG.md``. This helper is the small library that does the
extraction — used both by the workflow (shell-out) and by operators
for local preview (``python scripts/extract_changelog.py v0.1.0``).

Usage:

    python scripts/extract_changelog.py v0.1.0
    # prints the body of the matching section, exclusive of the
    # heading line itself. Exits 1 with a clear error if the version
    # isn't found.

The extraction is regex-based to keep the dependency footprint zero —
the release workflow runs against the smallest possible Python image.

Section format expected (matches Keep-a-Changelog convention):

    ## [vX.Y.Z] - YYYY-MM-DD      ← matched as the heading
    optional preamble                ← included in output
    ### Added                        ← included in output
    - bullet
    ...
    ## [previous version]            ← terminates the section
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def _normalise_version(version: str) -> str:
    """Strip an optional leading ``v`` so callers can pass either form."""
    return version[1:] if version.startswith("v") else version


def extract_section(changelog: str, version: str) -> str:
    """Return the body of the ``## [vX.Y.Z]`` section matching ``version``.

    :param changelog: Full ``CHANGELOG.md`` text.
    :param version: Either ``v0.1.0`` or ``0.1.0`` — both forms work.
    :raises LookupError: If no ``## [vX.Y.Z]`` heading exists for the
        requested version. Operators will see this as a non-zero exit
        with the version printed; the release workflow surfaces it via
        ``set -euo pipefail``.
    :return: Section body, stripped of leading/trailing whitespace.
    """
    normalised = _normalise_version(version)

    # Match ``## [v0.1.0]`` (or ``## [0.1.0]`` — both forms exist in
    # the wild). The trailing ``[^\n]*\n`` swallows any "- DATE"
    # suffix. The lookahead terminates at the next ``## `` heading or
    # end of file.
    patterns = [
        rf"^## \[v{re.escape(normalised)}\][^\n]*\n(.*?)(?=^## \[|\Z)",
        rf"^## \[{re.escape(normalised)}\][^\n]*\n(.*?)(?=^## \[|\Z)",
    ]
    for pat in patterns:
        match = re.search(pat, changelog, re.MULTILINE | re.DOTALL)
        if match:
            return match.group(1).strip()

    raise LookupError(
        f"no `## [v{normalised}]` heading in CHANGELOG.md — "
        f"promote `## [Unreleased]` to `## [v{normalised}]` before "
        f"tagging the release"
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint — print the extracted body or exit non-zero."""
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        print(
            "usage: extract_changelog.py <version>",
            file=sys.stderr,
        )
        return 2

    version = args[0]
    changelog_path = Path("CHANGELOG.md")
    if not changelog_path.is_file():
        print(
            "ERROR: CHANGELOG.md not found in the current working "
            "directory",
            file=sys.stderr,
        )
        return 1

    try:
        body = extract_section(changelog_path.read_text(), version)
    except LookupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
