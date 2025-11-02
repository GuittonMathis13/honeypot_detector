# tests/test_analyzer.py
# Offline unit tests for rules/report.

from __future__ import annotations

from backend import rules
from backend.report import build_report


def test_run_all_checks_with_source():
    """
    With source available, heuristics should pick up common risk patterns,
    including Pausable inheritance and custom LP pair vars.
    """
    fake_code = """
    // ===== Fees & taxes =====
    function setFee(uint256 f) external onlyOwner {}
    function setFees(uint256 b, uint256 s) external onlyOwner {}

    // ===== Black/white lists & limits =====
    mapping(address => bool) blacklist;
    function setMaxTx(uint256 v) external onlyOwner {}
    uint256 public maxWalletSize;

    // ===== Owner control =====
    modifier onlyOwner() { _; }
    function owner() public view returns (address) { return address(0x123); }

    // ===== Minting =====
    function mint(address to, uint256 a) external onlyOwner {}
    function _mint(address to, uint256 a) internal {}

    // ===== Pausable / Trading =====
    import "@openzeppelin/contracts/security/Pausable.sol";
    contract TokenX is Pausable {
        function pause() external onlyOwner {}
        function unpause() external onlyOwner {}
        bool public tradingOpen;
        function setTrading(bool v) external onlyOwner { tradingOpen = v; }
    }

    // ===== Uniswap restriction with custom var =====
    address public lpPair;
    function _transfer(address from, address to, uint256 amount) internal {
        require(to != lpPair, "blocked");
    }

    // ===== Proxy / delegatecall =====
    function _proxyForward(bytes memory data) internal returns (bytes memory) {
        (bool ok, bytes memory res) = address(impl).delegatecall(data);
        return res;
    }
    """

    flags = rules.run_all_checks(fake_code, source_available=True)

    assert flags["modifiable_fee"] is True
    assert flags["blacklist_whitelist"] is True
    assert flags["uniswap_restriction"] is True    # lpPair caught
    assert flags["owner_not_renounced"] is True
    assert flags["minting"] is True
    assert flags["pause_trading"] is True          # Pausable + tradingOpen
    assert flags["transfer_limits"] is True
    assert flags["proxy_pattern"] is True
    assert flags["unverified_code"] is False


def test_unverified_without_source():
    """If source is not available, only 'unverified_code' should be True."""
    flags = rules.run_all_checks("", source_available=False)
    assert flags["unverified_code"] is True
    for k in (
        "modifiable_fee","blacklist_whitelist","uniswap_restriction",
        "owner_not_renounced","minting","pause_trading","transfer_limits","proxy_pattern"
    ):
        assert flags[k] is False


def test_build_report_scoring_and_risk():
    """Smoke test for report shaping."""
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
    assert rep["risk"] in {"SAFE", "MEDIUM", "HIGH"}
    assert isinstance(rep["score"], int)
    assert isinstance(rep["summary"], str)
    assert set(rep["flags"]).issubset({k for k, v in flags.items() if v})
