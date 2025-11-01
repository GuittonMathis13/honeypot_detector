"""
report.py
This module provides functionality to transform raw flag data produced by
`rules.run_all_checks` into a human‑readable risk score, category and
summary. The scoring heuristic weights certain flags more heavily based
on the prevalence and severity of honeypot behaviour reported in
industry resources【933481489912976†L374-L399】. The summary sentences are meant
to be concise and understandable for non‑technical users.
"""

from __future__ import annotations
from typing import Dict, List, Tuple


# Assign weights to each flag. Heavier weights indicate higher risk.
# These values were chosen to produce a score between 0 and 10 for
# typical combinations of flags; they can be tuned in the future.
FLAG_WEIGHTS: Dict[str, int] = {
    "modifiable_fee": 2,
    "blacklist_whitelist": 2,
    "uniswap_restriction": 3,
    "owner_not_renounced": 1,
    "minting": 2,
    "pause_trading": 1,
    "unverified_code": 3,
    "transfer_limits": 2,
    "proxy_pattern": 2,
}


# Human‑readable descriptions for each flag used in the summary.
FLAG_DESCRIPTIONS: Dict[str, str] = {
    "modifiable_fee": "Contract allows tax or fee parameters to be modified by privileged accounts.",
    "blacklist_whitelist": "Contract contains blacklist/whitelist or transfer restrictions that can block users.",
    "uniswap_restriction": "Contract restricts selling via the liquidity pool (potential honeypot).",
    "owner_not_renounced": "Ownership is active and `onlyOwner` functions exist without renunciation.",
    "minting": "Mint function detected – supply can be increased at will.",
    "pause_trading": "Trading can be paused or resumed by the owner.",
    "unverified_code": "Source code is unverified; logic cannot be audited.",
    "transfer_limits": "Contract imposes maximum transaction or wallet limits, which can restrict users from selling or transferring.",
    "proxy_pattern": "Contract uses delegatecall or proxy pattern; logic may be upgraded after deployment.",
}


def compute_score(flags: Dict[str, bool]) -> int:
    """Compute a risk score between 0 and 10 from the active flags."""
    score = 0
    for flag, active in flags.items():
        if active:
            score += FLAG_WEIGHTS.get(flag, 0)
    # Cap the score at 10
    return min(score, 10)


def classify_risk(score: int) -> str:
    """
    Convert a numeric score into a qualitative risk category.

    * 0–3 → SAFE
    * 4–6 → MEDIUM
    * 7–10 → HIGH
    """
    if score <= 3:
        return "SAFE"
    if score <= 6:
        return "MEDIUM"
    return "HIGH"


def generate_summary(flags: Dict[str, bool]) -> str:
    """
    Build a short textual summary from the active flags. If no flags
    are active, a benign message is returned.
    """
    active_descriptions: List[str] = [
        desc for flag, desc in FLAG_DESCRIPTIONS.items() if flags.get(flag)
    ]
    if not active_descriptions:
        return "No obvious red flags detected in the contract source."
    return " ".join(active_descriptions)


def build_report(address: str, flags: Dict[str, bool]) -> Dict[str, object]:
    """
    Assemble the final report dictionary from an address and its flags.
    Includes the computed score, risk category, list of flag names and
    a human‑readable summary.
    """
    score = compute_score(flags)
    risk = classify_risk(score)
    summary = generate_summary(flags)
    active_flags = [flag for flag, active in flags.items() if active]
    return {
        "address": address,
        "score": score,
        "risk": risk,
        "flags": active_flags,
        "summary": summary,
    }