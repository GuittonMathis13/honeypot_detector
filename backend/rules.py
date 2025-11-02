"""
rules.py
Heuristic checks on Solidity source to surface common honeypot / rug red flags.
"""

from __future__ import annotations
import re
from typing import Dict


def check_modifiable_fee(code: str) -> bool:
    """
    Owner/privileged can change fees/taxes.
    """
    patterns = [
        "settax", "setfee", "setfees", "updatetax",
        "buyfee", "sellfee", "changetax",
    ]
    code_lower = code.lower()
    return any(p in code_lower for p in patterns)


def check_blacklist_whitelist(code: str) -> bool:
    """
    Black/white list or similar user restrictions.
    """
    patterns = [
        "blacklist", "whitelist", "setmaxtx", "maxwallet",
        "banuser", "blocklist", "removeliquidity",
    ]
    code_lower = code.lower()
    return any(p in code_lower for p in patterns)


def check_uniswap_restriction(code: str) -> bool:
    """
    Block sells by forbidding transfers to LP/pair/uniswap.
    Robust against custom var names (pair, lpPair, uPair, etc).
    We normalize by removing spaces and lowercasing.
    """
    norm = re.sub(r"\s+", "", code.lower())

    # Patterns like: require(to!=uniswapV2Pair), require(_to != pair), require(recipient != lpPair)
    # - look for 'require(' ... (to|_to|recipient) ... '!=' ... (uniswap*|*pair*)
    pat = re.compile(
        r"require\([^)]*(?:to|_to|recipient)[^!]*!=[^)]*(?:uniswap[a-z0-9_]*|[a-z0-9_]*pair[a-z0-9_]*)",
        re.IGNORECASE,
    )
    return bool(pat.search(norm))


def check_owner_functions(code: str) -> bool:
    """
    Centralized control: many onlyOwner restrictions and no renounceOwnership.
    - Count real 'onlyOwner' modifier occurrences (word boundary)
    - If 'renounceOwnership' (or similar) is present, we consider potential mitigation
    """
    code_lower = code.lower()
    only_owner_count = len(re.findall(r"\bonlyowner\b", code_lower))
    has_renounce = "renounceownership" in code_lower or "renounceowner" in code_lower
    has_owner_function = "function owner" in code_lower or "owner()" in code_lower

    # Keep similar threshold but with real modifier detection
    return (only_owner_count > 2 and not has_renounce) or (has_owner_function and not has_renounce)


def check_minting(code: str) -> bool:
    """
    Hidden supply increase.
    """
    code_lower = code.lower()
    return "_mint(" in code_lower or "function mint" in code_lower


def check_pause_trading(code: str) -> bool:
    """
    Ability to halt trading (Pausable or equivalents).
    - Detect OZ Pausable (import / inheritance)
    - Detect common functions/vars: pause, unpause, tradingOpen, tradingEnabled, setTrading, enableTrading
    """
    cl = code.lower()
    pausable_signals = [
        "import '@openzeppelin/contracts/security/pausable'",
        'import "@openzeppelin/contracts/security/pausable"',
        " is pausable",
    ]
    func_signals = [
        "pausetrading", "pause()", "unpause()", "pause", "unpause",
        "settrading", "enabletrading",
        "tradingopen", "tradingenabled",  # vars frequently used
    ]
    return any(s in cl for s in pausable_signals) or any(s in cl for s in func_signals)


def check_proxy_pattern(code: str) -> bool:
    """
    Proxy/upgradeability hints.
    """
    code_lower = code.lower().replace(" ", "")
    patterns = [
        "delegatecall(",
        "eip1967",
        "implementation",
        "proxy",
    ]
    return any(p in code_lower for p in patterns)


def check_transfer_limits(code: str) -> bool:
    """
    Max tx / max wallet constraints (basic detection).
    """
    code_lower = code.lower()
    patterns = [
        "setmaxtx", "maxtx", "maxwallet", "maxwalletsize",
        "maxsell", "maxbuy", "maxtransactionamount", "maxtransaction",
    ]
    return any(p in code_lower for p in patterns)


def check_unverified_code(source_code: str) -> bool:
    """
    True if no verified source was found.
    """
    return not source_code or len(source_code.strip()) == 0


def run_all_checks(code: str, source_available: bool) -> Dict[str, bool]:
    """
    Run all checks and return flag dict.
    """
    flags = {
        "modifiable_fee": check_modifiable_fee(code) if source_available else False,
        "blacklist_whitelist": check_blacklist_whitelist(code) if source_available else False,
        "uniswap_restriction": check_uniswap_restriction(code) if source_available else False,
        "owner_not_renounced": check_owner_functions(code) if source_available else False,
        "minting": check_minting(code) if source_available else False,
        "pause_trading": check_pause_trading(code) if source_available else False,
        "unverified_code": check_unverified_code(code) if not source_available else False,
        "transfer_limits": check_transfer_limits(code) if source_available else False,
        "proxy_pattern": check_proxy_pattern(code) if source_available else False,
    }
    return flags
