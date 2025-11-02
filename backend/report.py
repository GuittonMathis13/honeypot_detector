"""
report.py — Honeypot Detector Pro (B1.3)
Builds a weighted score (0–10) and generates a professional summary.
"""

from __future__ import annotations
from typing import Dict, Any

# --- 1️⃣ Flag weight mapping (risk intensity) ---

FLAG_WEIGHTS = {
    # High-risk
    "owner_not_renounced": 3,
    "blacklist_whitelist": 3,
    "uniswap_restriction": 3,
    "modifiable_fee": 3,

    # Medium-risk
    "minting": 2,
    "pause_trading": 2,
    "transfer_limits": 2,
    "proxy_pattern": 2,

    # Light-risk / informational
    "max_limits_strict": 1,
    "dynamic_fees_public": 1,
    "transfer_trap": 1,
}

MAX_SCORE = 10


# --- 2️⃣ Risk level helper ---

def classify_risk(score: int) -> str:
    if score <= 3:
        return "SAFE"
    elif score <= 6:
        return "MEDIUM"
    else:
        return "HIGH"


# --- 3️⃣ Human-readable summary builder ---

def build_summary(flags: Dict[str, bool]) -> str:
    messages = []
    add = messages.append

    if flags.get("owner_not_renounced"):
        add("Ownership is active; contract remains under centralised control.")
    if flags.get("modifiable_fee"):
        add("Transaction fees or taxes can be modified by privileged addresses.")
    if flags.get("blacklist_whitelist"):
        add("Contract includes blacklist/whitelist logic that can block users.")
    if flags.get("uniswap_restriction"):
        add("Transfers to liquidity pools may be restricted, blocking sales.")
    if flags.get("minting"):
        add("Owner can mint new tokens, increasing supply arbitrarily.")
    if flags.get("pause_trading"):
        add("Trading can be paused or resumed by an admin.")
    if flags.get("transfer_limits"):
        add("Maximum wallet or transaction limits are enforced.")
    if flags.get("proxy_pattern"):
        add("Proxy or delegatecall detected: contract logic can be upgraded.")
    if flags.get("max_limits_strict"):
        add("Limits on transactions are extremely low (<2%).")
    if flags.get("dynamic_fees_public"):
        add("Public fee variables and setters suggest dynamic taxation.")
    if flags.get("transfer_trap"):
        add("Transfer function restricts interactions with the owner address.")

    if not messages:
        return "No significant risks detected — contract appears safe."
    return " ".join(messages)


# --- 4️⃣ Main builder ---

def build_report(address: str, flags: Dict[str, bool]) -> Dict[str, Any]:
    score = 0
    for flag, enabled in flags.items():
        if enabled:
            score += FLAG_WEIGHTS.get(flag, 1)

    score = min(score, MAX_SCORE)
    risk = classify_risk(score)
    summary = build_summary(flags)

    return {
        "address": address,
        "score": score,
        "risk": risk,
        "flags": [k for k, v in flags.items() if v],
        "summary": summary,
    }
