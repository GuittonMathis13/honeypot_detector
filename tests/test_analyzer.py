# tests/test_analyzer.py
# Minimal, fast, and offline tests for the analysis logic.

from __future__ import annotations

from backend import rules
from backend.report import build_report


def test_run_all_checks_with_source():
    """
    With source available, heuristics should pick up common risk patterns.
    """
    fake_code = """
    // Fees & taxes
    function setFee(uint256 f) external onlyOwner {}
    function setFees(uint256 b, uint256 s) external onlyOwner {}
    // Black/white lists & limits
    mapping(address => bool) blacklist;
    function setMaxTx(uint256 v) external onlyOwner {}
    // Owner control
    modifier onlyOwner() { _; } function owner() public view returns (address) { return address(0x123); }
    // Minting
    function mint(address to, uint256 a) external onlyOwner {}
    function _mint(address to, uint256 a) internal {}
    // Pause/Trading
    function pause() external onlyOwner {}
    function unpause() external onlyOwner {}
    function enableTrading() external onlyOwner {}
    // Uniswap restriction
    function _transfer(address from, address to, uint256 amount) internal {
        require(to != uniswapV2Pair, "blocked");
    }
    // Proxy / delegatecall
    function _proxyForward(bytes memory data) internal returns (bytes memory) {
        (bool ok, bytes memory res) = address(impl).delegatecall(data);
        return res;
    }
    // No renounce
    """

    flags = rules.run_all_checks(fake_code, source_available=True)

    assert flags["modifiable_fee"] is True
    assert flags["blacklist_whitelist"] is True
    assert flags["uniswap_restriction"] is True
    assert flags["owner_not_renounced"] is True
    assert flags["minting"] is True
    assert flags["pause_trading"] is True
    assert flags["transfer_limits"] is True
    assert flags["proxy_pattern"] is True
    assert flags["unverified_code"] is False  # because source_available=True


def test_unverified_without_source():
    """
    If source is not available, the 'unverified_code' flag should be True.
    """
    flags = rules.run_all_checks("", source_available=False)
    assert flags["unverified_code"] is True
    # Others should be False when source is unavailable
    assert flags["modifiable_fee"] is False
    assert flags["blacklist_whitelist"] is False
    assert flags["uniswap_restriction"] is False
    assert flags["owner_not_renounced"] is False
    assert flags["minting"] is False
    assert flags["pause_trading"] is False
    assert flags["transfer_limits"] is False
    assert flags["proxy_pattern"] is False


def test_build_report_scoring_and_risk():
    """
    Smoke test for scoring + risk mapping.
    """
    flags = {
        "modifiable_fee": True,
        "blacklist_whitelist": True,
        "uniswap_restriction": False,
        "owner_not_renounced": True,
        "minting": False,
        "pause_trading": True,
        "unverified_code": False,
        "transfer_limits": True,
        "proxy_pattern": True,
    }
    rep = build_report(address="0xTEST", flags=flags)

    assert rep["address"] == "0xTEST"
    assert isinstance(rep["score"], int)
    assert rep["risk"] in {"SAFE", "MEDIUM", "HIGH"}
    assert "summary" in rep and isinstance(rep["summary"], str)
    # Flags list should only contain those set to True
    for f in rep["flags"]:
        assert flags[f] is True
