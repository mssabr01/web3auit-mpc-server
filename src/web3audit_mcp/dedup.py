"""Cross-tool finding deduplication.

Slither and Aderyn often flag the same bug.  This module merges duplicates
by comparing (detector_class, affected_locations, description) using both
exact and fuzzy matching so you get one canonical finding per real issue.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from itertools import combinations

from thefuzz import fuzz

from .models import Finding, Severity

logger = logging.getLogger(__name__)

# Tuning knobs
_TITLE_FUZZY_THRESHOLD = 75  # 0-100, higher = stricter
_DESC_FUZZY_THRESHOLD = 65
_LOCATION_OVERLAP_THRESHOLD = 0.5  # fraction of shared files+lines

# Detector families that are semantically equivalent across tools
_DETECTOR_ALIASES: dict[str, str] = {
    # Reentrancy variants
    "slither:reentrancy-eth": "reentrancy",
    "slither:reentrancy-no-eth": "reentrancy",
    "slither:reentrancy-benign": "reentrancy",
    "slither:reentrancy-events": "reentrancy",
    "slither:reentrancy-unlimited-gas": "reentrancy",
    "aderyn:reentrancy": "reentrancy",
    "aderyn:state-change-after-external-call": "reentrancy",
    # Unused return values
    "slither:unused-return": "unused-return",
    "aderyn:unused-return": "unused-return",
    # Unchecked low-level
    "slither:low-level-calls": "low-level-calls",
    "aderyn:low-level-calls": "low-level-calls",
    # tx.origin
    "slither:tx-origin": "tx-origin",
    "aderyn:tx-origin-auth": "tx-origin",
    # Uninitialized storage
    "slither:uninitialized-storage": "uninit-storage",
    "aderyn:uninitialized-storage": "uninit-storage",
    # Delegatecall
    "slither:controlled-delegatecall": "controlled-delegatecall",
    "aderyn:delegatecall-in-loop": "controlled-delegatecall",
}


def _canonical_detector(detector: str) -> str:
    return _DETECTOR_ALIASES.get(detector, detector)


def _location_keys(finding: Finding) -> set[str]:
    """Return a set of normalised file:line tokens for overlap comparison."""
    keys: set[str] = set()
    for loc in finding.locations:
        base = loc.file
        if loc.line_start is not None:
            # bucket to nearest 5-line window to allow slight offsets
            bucket = (loc.line_start // 5) * 5
            base += f":{bucket}"
        keys.add(base)
    return keys


def _locations_overlap(a: Finding, b: Finding) -> float:
    """Jaccard overlap of location keys."""
    ka, kb = _location_keys(a), _location_keys(b)
    if not ka or not kb:
        return 0.0
    return len(ka & kb) / len(ka | kb)


def _pick_winner(a: Finding, b: Finding) -> Finding:
    """Choose the richer finding, merge metadata from the loser."""
    # Prefer higher severity, then higher confidence, then longer description
    winner, loser = a, b
    if (
        b.severity.rank < a.severity.rank
        or (b.severity.rank == a.severity.rank and b.confidence.rank < a.confidence.rank)
        or (b.severity == a.severity and b.confidence == a.confidence
            and len(b.description) > len(a.description))
    ):
        winner, loser = b, a

    # Merge references and extra locations
    merged_refs = list(dict.fromkeys(winner.references + loser.references))
    merged_locs = winner.locations[:]
    existing_keys = {l.key for l in merged_locs}
    for loc in loser.locations:
        if loc.key not in existing_keys:
            merged_locs.append(loc)

    return winner.model_copy(update={
        "references": merged_refs,
        "locations": merged_locs,
    })


def deduplicate(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Remove duplicate findings across tools.

    Returns (deduplicated_findings, number_removed).
    """
    if len(findings) <= 1:
        return findings, 0

    # Group by canonical detector family
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[_canonical_detector(f.detector)].append(f)

    kept: list[Finding] = []
    removed = 0

    for _family, group in groups.items():
        if len(group) == 1:
            kept.append(group[0])
            continue

        # Within the group, pairwise compare
        merged_away: set[int] = set()
        indexed = list(enumerate(group))

        for (i, a), (j, b) in combinations(indexed, 2):
            if i in merged_away or j in merged_away:
                continue

            # Same tool?  Let both through (they're different instances)
            if a.source_tool == b.source_tool:
                # But still check if they point to the exact same location
                if _locations_overlap(a, b) < 0.8:
                    continue

            # Check similarity
            title_score = fuzz.token_sort_ratio(a.title, b.title)
            loc_overlap = _locations_overlap(a, b)

            # Strip Solidity source snippets before comparing descriptions
            desc_a = re.sub(r"`[^`]+`", "", a.description)
            desc_b = re.sub(r"`[^`]+`", "", b.description)
            desc_score = fuzz.token_sort_ratio(desc_a, desc_b) if desc_a and desc_b else 0

            is_dup = (
                loc_overlap >= _LOCATION_OVERLAP_THRESHOLD
                and (title_score >= _TITLE_FUZZY_THRESHOLD or desc_score >= _DESC_FUZZY_THRESHOLD)
            )

            if is_dup:
                winner = _pick_winner(a, b)
                # Replace whichever survived
                if winner is a:
                    merged_away.add(j)
                    group[i] = winner
                else:
                    merged_away.add(i)
                    group[j] = winner
                removed += 1
                logger.debug("Dedup merged %s ↔ %s", a.detector, b.detector)

        for idx, f in enumerate(group):
            if idx not in merged_away:
                kept.append(f)

    # Sort by severity, then title
    kept.sort(key=lambda f: (f.severity.rank, f.title))
    return kept, removed
