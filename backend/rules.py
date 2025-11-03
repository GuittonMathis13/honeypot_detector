"""
    rules.py — Honeypot Detector Pro (B1.3 — Clean)
    Heuristics on Solidity source strings → boolean risk flags.

    Changement clé : suppression du HOTFIX qui forçait owner_not_renounced=True.
    On implémente une vraie détection :
      - Présence d’owner/onlyOwner => contrôle possible
      - Si renounceOwnership() ou transferOwnership(address(0)) détectés => on NE
        déclenche PAS le flag owner_not_renounced
"""

from __future__ import annotations
import re
from typing import Dict


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def _normalize(code: str) -> str:
    """Minifie et normalise la casse + espaces pour les recherches rapides."""
    return code.lower().replace(" ", "").replace("\n", "")


# ------------------------------------------------------------
# Core detection rules
# ------------------------------------------------------------
def check_modifiable_fee(code: str) -> bool:
    s = code.lower()
    patterns = ["settax", "setfee", "setfees", "updatetax", "buyfee", "sellfee", "changetax"]
    return any(p in s for p in patterns)


def check_blacklist_whitelist(code: str) -> bool:
    s = code.lower()
    patterns = ["blacklist", "whitelist", "blocklist", "banuser", "setmaxtx", "maxwallet", "removeliquidity"]
    return any(p in s for p in patterns)


_UNISWAP_PAIR_RE = re.compile(r"require\s*\(\s*(?:_?to)\s*!=\s*([a-zA-Z_]\w*)\s*[,)]", re.IGNORECASE)


def check_uniswap_restriction(code: str) -> bool:
    compact = _normalize(code)
    if any(q in compact for q in ["require(to!=uniswap", "to!=uniswappair", "to!=uniswapv2pair"]):
        return True
    for m in _UNISWAP_PAIR_RE.finditer(code):
        if "pair" in m.group(1).lower():
            return True
    return False


def check_minting(code: str) -> bool:
    s = code.lower()
    return "_mint(" in s or "function mint" in s


def check_pause_trading(code: str) -> bool:
    s = code.lower()
    pausable = ["whennotpaused", "whenpaused", "paused()", "pausable"]
    trading = ["pausetrading", "settrading", "enabletrading", "tradingopen", "opentrading"]
    return any(p in s for p in pausable + trading)


def check_proxy_pattern(code: str) -> bool:
    compact = _normalize(code)
    return any(p in compact for p in ["delegatecall(", "eip1967", "implementation", "proxy"])


def check_transfer_limits(code: str) -> bool:
    s = code.lower()
    patterns = ["setmaxtx", "maxtx", "maxwallet", "maxwalletsize", "maxsell", "maxbuy", "maxtransactionamount", "maxtransaction"]
    return any(p in s for p in patterns)


def check_unverified_code(source_code: str) -> bool:
    return not source_code or len(source_code.strip()) == 0


# ------------------------------------------------------------
# Owner / renounce detection
# ------------------------------------------------------------
OWNABLE_RE = re.compile(r"\b(?:onlyOwner|owner\s*\()", re.IGNORECASE)
RENOUNCE_RE = re.compile(r"\brenounceOwnership\s*\(", re.IGNORECASE)
ZERO_OWNER_SET_RE = re.compile(r"transferOwnership\s*\(\s*address\s*\(\s*0\s*\)\s*\)", re.IGNORECASE)


def check_owner_not_renounced(code: str, source_available: bool) -> bool:
    """
    True si contrôle 'owner' apparent ET aucun indice crédible de renonciation.
    False si pas de source, pas d'owner, ou si renonciation détectée.
    """
    if not source_available:
        return False
    s = code
    has_owner_controls = bool(OWNABLE_RE.search(s))
    if not has_owner_controls:
        return False
    # Si on voit une renonciation explicite, on ne trigger pas le flag
    if RENOUNCE_RE.search(s) or ZERO_OWNER_SET_RE.search(s):
        return False
    return True


# ------------------------------------------------------------
# B1.2 extended rules
# ------------------------------------------------------------
def check_max_limits_strict(code: str) -> bool:
    s = code.lower()
    for m in re.finditer(r"max\w*percent\s*=\s*(\d{1,2})", s):
        try:
            if int(m.group(1)) <= 2:
                return True
        except Exception:
            pass
    if ("maxwalletpercent" in s or "maxtxpercent" in s) and re.search(r"(max\w*percent)[^;]{0,80}=\s*[12]\b", s):
        return True
    return False


def check_dynamic_fees_public(code: str) -> bool:
    s = code.lower()
    has_public_fee = bool(re.search(r"\b(?:u?int(?:256)?)\s+public\s+\w*(?:fee|tax)\w*", s))
    has_setter = any(k in s for k in ("setfee", "setfees", "settax", "updatetax"))
    return has_public_fee and has_setter


def check_transfer_trap(code: str) -> bool:
    compact = _normalize(code)
    patterns = [
        "require(from!=owner", "require(_from!=owner",
        "require(to!=owner", "require(_to!=owner",
        "require(from==owner", "require(_from==owner",
        "require(to==owner", "require(_to==owner",
    ]
    return any(p in compact for p in patterns)


# ------------------------------------------------------------
# Main dispatcher
# ------------------------------------------------------------
def run_all_checks(code: str, source_available: bool) -> Dict[str, bool]:
    """Run all heuristic checks and return boolean flags."""
    flags = {
        "modifiable_fee": check_modifiable_fee(code) if source_available else False,
        "blacklist_whitelist": check_blacklist_whitelist(code) if source_available else False,
        "uniswap_restriction": check_uniswap_restriction(code) if source_available else False,

        # ✅ vraie détection (plus de hotfix forcé)
        "owner_not_renounced": check_owner_not_renounced(code, source_available),

        "minting": check_minting(code) if source_available else False,
        "pause_trading": check_pause_trading(code) if source_available else False,
        "unverified_code": check_unverified_code(code) if not source_available else False,
        "transfer_limits": check_transfer_limits(code) if source_available else False,
        "proxy_pattern": check_proxy_pattern(code) if source_available else False,

        # Extended B1.2
        "max_limits_strict": check_max_limits_strict(code) if source_available else False,
        "dynamic_fees_public": check_dynamic_fees_public(code) if source_available else False,
        "transfer_trap": check_transfer_trap(code) if source_available else False,
    }
    return flags
