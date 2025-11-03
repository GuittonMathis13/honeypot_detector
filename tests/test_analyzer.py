# tests/test_analyzer.py — B1.2
from __future__ import annotations

from backend import rules
from backend.report import build_report


def test_run_all_checks_with_source():
    fake_code = """
    // ===== Fees & taxes =====
    uint256 public buyFee = 10;
    function setFee(uint256 f) external onlyOwner { buyFee = f; }
    function setFees(uint256 b, uint256 s) external onlyOwner {}

    // ===== Black/white lists & limits =====
    mapping(address => bool) blacklist;
    function setMaxTx(uint256 v) external onlyOwner {}
    uint256 maxTxPercent = 1;           // <= 2%
    uint256 maxWalletPercent = 2;       // <= 2%

    // ===== Owner control (Ownable + onlyOwner; no renounce) =====
    contract X is Ownable {
        modifier onlyOwner() { _; }
        function owner() public view returns (address) { return address(0x123); }
    }

    // ===== Minting =====
    function mint(address to, uint256 a) external onlyOwner {}
    function _mint(address to, uint256 a) internal {}

    // ===== Pause/Trading (OZ + toggles) =====
    function pause() external onlyOwner {}
    function unpause() external onlyOwner {}
    function enableTrading() external onlyOwner {}
    function openTrading() external onlyOwner {}
    function _before() internal whenNotPaused {}
    function _after() internal whenPaused {}

    // ===== Uniswap restriction (generic pair var) =====
    address public lpPair;
    function _transfer(address from, address to, uint256 amount) internal {
        require(to != lpPair, "blocked");
        require(from != owner() && to != owner(), "trap");
    }

    // ===== Proxy / delegatecall =====
    function _proxyForward(bytes memory data) internal returns (bytes memory) {
        (bool ok, bytes memory res) = address(impl).delegatecall(data);
        return res;
    }
    // No renounceOwnership present on purpose
    """

    flags = rules.run_all_checks(fake_code, source_available=True)

    # Existing checks
    assert flags["modifiable_fee"] is True
    assert flags["blacklist_whitelist"] is True
    assert flags["uniswap_restriction"] is True
    assert flags["owner_not_renounced"] is True
    assert flags["minting"] is True
    assert flags["pause_trading"] is True
    assert flags["transfer_limits"] is True
    assert flags["proxy_pattern"] is True
    assert flags["unverified_code"] is False  # source_available=True

    # New B1.2 checks
    assert flags["max_limits_strict"] is True
    assert flags["dynamic_fees_public"] is True
    assert flags["transfer_trap"] is True


def test_unverified_without_source():
    flags = rules.run_all_checks("", source_available=False)
    assert flags["unverified_code"] is True
    for k in (
        "modifiable_fee", "blacklist_whitelist", "uniswap_restriction",
        "owner_not_renounced", "minting", "pause_trading",
        "transfer_limits", "proxy_pattern",
        "max_limits_strict", "dynamic_fees_public", "transfer_trap",
    ):
        assert flags[k] is False


def test_build_report_scoring_and_risk():
    # NOTE: B1.3 will adjust scoring to include new flags.
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
        "max_limits_strict": True,
        "dynamic_fees_public": True,
        "transfer_trap": True,
    }
    rep = build_report(address="0xTEST", flags=flags)
    assert rep["address"] == "0xTEST"
    assert isinstance(rep["score"], int)
    assert rep["risk"] in {"SAFE", "MEDIUM", "HIGH"}
    assert isinstance(rep["summary"], str)
    assert set(rep["flags"]).issubset({k for k, v in flags.items() if v})