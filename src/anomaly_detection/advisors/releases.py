"""Upstream Kubernetes support windows.

Dated 2026-09-29 from https://kubernetes.io/releases/. The project maintains
the newest three minors; the previous minor stays in maintenance until its
end-of-life date. Refresh this table when cutting a release.
"""

from __future__ import annotations

from datetime import date

CATALOG_AS_OF = date(2026, 9, 29)
CATALOG_URL = "https://kubernetes.io/releases/"

# minor -> maintenance start, end of life, newest patch known to this catalog
RELEASES: dict[int, dict] = {
    31: {"maintenance": date(2025, 9, 11), "eol": date(2025, 11, 11), "latest": "1.31.14"},
    32: {"maintenance": date(2025, 12, 28), "eol": date(2026, 2, 28), "latest": "1.32.13"},
    33: {"maintenance": date(2026, 4, 28), "eol": date(2026, 6, 28), "latest": "1.33.13"},
    34: {"maintenance": date(2026, 8, 27), "eol": date(2026, 10, 27), "latest": "1.34.12"},
    35: {"maintenance": date(2026, 12, 28), "eol": date(2027, 2, 28), "latest": "1.35.9"},
    36: {"maintenance": date(2027, 4, 28), "eol": date(2027, 6, 28), "latest": "1.36.5"},
    37: {"maintenance": date(2027, 8, 28), "eol": date(2027, 10, 28), "latest": "1.37.1"},
}

# kubelet may trail kube-apiserver by at most this many minors.
MAX_KUBELET_SKEW = 3


def parse_version(raw: str) -> tuple[int, int] | None:
    text = (raw or "").removeprefix("v").split("-", 1)[0]
    parts = text.split(".")
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
        return None
    patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
    return int(parts[1]), patch
