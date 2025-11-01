"""
rules.py
This module contains a collection of helper functions that operate on Solidity
source code strings and return boolean flags indicating whether certain
risk patterns are present. These heuristics are derived from common
red flags described in security analyses and scanners such as Token Sniffer,
including functions that modify taxes, impose blacklists or whitelists,
restrict sales to certain pairs, expose privileged owner operations and
unverified code.
"""

from __future__ import annotations
import re
from typing import Dict


def check_modifiable_fee(code: str) -> bool:
    """
    Returns True if the contract contains functions that allow the owner
    or privileged roles to change transaction taxes or fees. Examples
    include setTax, setFee, buyFee and sellFee functions. The detection
    is case-insensitive and searches for common patterns reported by scanners.
    """
    patterns = [
        "settax",
        "setfee",
        "setfees",
        "updatetax",
        "buyfee",
        "sellfee",
        "changetax",
    ]
    code_lower = code.lower()
    return any(p in code_lower for p in patterns)


def check_blacklist_whitelist(code: str) -> bool:
    """
    Returns True if the contract contains blacklist, whitelist or other
    user-restriction mechanisms. Contracts that permit a privileged address
    to ban or allow specific users are considered high risk because they
    can arbitrarily freeze user funds.
    """
    patterns = [
        "blacklist",
        "whitelist",
        "setmaxtx",   # often used to limit transfers
        "maxwallet",
        "banuser",
        "blocklist",
        "removeliquidity",
    ]
    code_lower = code.lower()
    return any(p in code_lower for p in patterns)


def check_uniswap_restriction(code: str) -> bool:
    """
    Detects attempts to prevent transfers to or from the Uniswap liquidity
    pool. Honeypot scams often include a clause like `require(to != uniswapPair)`
    which blocks selling.
    """
    code_lower = code.lower().replace(" ", "")
    restricted_keywords = [
        "require(to!=uniswap",
        "require(_to!=uniswap",
        "to!=uniswappair",
        "to!=uniswapv2pair",
    ]
    return any(key in code_lower for key in restricted_keywords)


def check_owner_functions(code: str) -> bool:
    """
    Determines if the contract retains significant control with an active owner.
    If the code contains many `onlyOwner` calls or defines an `owner()` function
    without renouncing ownership, it suggests centralised control.
    This function returns True when `onlyOwner` appears multiple times or the
    owner can renounce but has not done so.
    """
    code_lower = code.lower()
    # Count occurrences of onlyOwner-like modifiers
    count_only_owner = len(re.findall(r"onlyowner", code_lower))
    # Identify explicit owner variable declarations and renounce logic
    has_renounce = "renounceownership" in code_lower or "renounceowner" in code_lower
    has_owner_function = "function owner" in code_lower or "owner()" in code_lower
    # Consider owner active if there are many onlyOwner calls and no renounce
    return (count_only_owner > 2 and not has_renounce) or (has_owner_function and not has_renounce)


def check_minting(code: str) -> bool:
    """
    Checks for mint functions that allow privileged addresses to increase supply.
    Hidden minting can dilute holders and is a known rug lever.
    """
    code_lower = code.lower()
    return "_mint(" in code_lower or "function mint" in code_lower


def check_pause_trading(code: str) -> bool:
    """
    Detects pause/unpause functionality that can halt trading arbitrarily.
    Contracts may include `pauseTrading`, `pause`, `unpause` or similar
    functions. Legitimate uses exist, but for this scanner any pause
    capability raises a caution flag.
    """
    code_lower = code.lower()
    patterns = [
        "pausetrading",
        "pause",        # less strict than "pause()" to avoid missing variants
        "unpause",      # less strict than "unpause()"
        "settrading",
        "enabletrading",
    ]
    return any(p in code_lower for p in patterns)


def check_proxy_pattern(code: str) -> bool:
    """
    Detects proxy or delegatecall usage which may indicate an upgradeable
    contract. While not inherently malicious, proxy patterns allow the
    logic to change after deployment, which can hide honeypot behaviour.
    The check searches for `delegatecall`, `proxy`, `eip1967` or `implementation`.
    """
    code_lower = code.lower().replace(" ", "")
    patterns = [
        "delegatecall(",
        "eip1967",        # common storage slot marker for proxies
        "implementation", # generic to catch many implementations
        "proxy",
    ]
    return any(p in code_lower for p in patterns)


def check_transfer_limits(code: str) -> bool:
    """
    Detects presence of maximum transaction or wallet limit functions. These
    restrictions (e.g. setMaxTx, maxTxPercent, maxWalletSize) can be used to
    prevent users from transferring or selling beyond trivial amounts, a common
    honeypot tactic.
    """
    code_lower = code.lower()
    patterns = [
        "setmaxtx",
        "maxtx",
        "maxwallet",
        "maxwalletsize",
        "maxsell",
        "maxbuy",
        "maxtransactionamount",
        "maxtransaction",  # generic pattern
    ]
    return any(p in code_lower for p in patterns)


def check_unverified_code(source_code: str) -> bool:
    """
    Returns True if the source code is empty. Unverified source code is a
    black box and therefore a serious risk.
    """
    return not source_code or len(source_code.strip()) == 0


def run_all_checks(code: str, source_available: bool) -> Dict[str, bool]:
    """
    Executes all risk checks and returns a dictionary of flag names mapped
    to boolean results. Additional checks can be added here for future
    analysis.
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
