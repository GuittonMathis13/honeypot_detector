"""
Unit tests for the Honeypot Detector Pro analysis logic.

These tests cover the behaviour of the flag detection functions in
`rules.py` and the report generation in `report.py`. They use
synthetic contract source snippets instead of fetching data from
Etherscan. The goal is to ensure that obvious patterns trigger the
expected flags and that the scoring logic behaves as intended.
"""

import pytest

from honeypot_detector.backend import rules, report, analyzer


# Sample Solidity snippets for testing
SIMPLE_ERC20 = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MyToken is ERC20 {
    constructor() ERC20("My Token", "MYT") {
        _mint(msg.sender, 1000000 * (10 ** decimals()));
    }
}
"""


HONEYPOT_SNIPPET = """
// Honeypot example with restrictive sell
pragma solidity ^0.8.0;

contract EvilToken {
    mapping(address => bool) private blacklist;
    address public owner;
    uint256 public buyFee;
    uint256 public sellFee;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setTax(uint256 _buy, uint256 _sell) external onlyOwner {
        buyFee = _buy;
        sellFee = _sell;
    }

    function addToBlacklist(address user) external onlyOwner {
        blacklist[user] = true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(to != uniswapPair, "no sell");
        super._transfer(from, to, amount);
    }
}
"""


def test_flag_detection_no_flags():
    flags = rules.run_all_checks(SIMPLE_ERC20, source_available=True)
    # All flags should be False except unverified_code (not triggered here)
    assert not any(flags.values())


def test_flag_detection_honeypot():
    flags = rules.run_all_checks(HONEYPOT_SNIPPET, source_available=True)
    assert flags["modifiable_fee"]
    assert flags["blacklist_whitelist"]
    assert flags["uniswap_restriction"]
    assert flags["owner_not_renounced"]  # owner and onlyOwner appear multiple times


def test_report_scoring():
    flags = {
        "modifiable_fee": True,
        "blacklist_whitelist": True,
        "uniswap_restriction": False,
        "owner_not_renounced": True,
        "minting": False,
        "pause_trading": False,
        "unverified_code": False,
        "transfer_limits": False,
        "proxy_pattern": False,
    }
    score = report.compute_score(flags)
    # weights: 2 + 2 + 1 = 5 → MEDIUM (transfer_limits and proxy_pattern inactive)
    assert score == 5
    assert report.classify_risk(score) == "MEDIUM"


def test_analyzer_stubbed():
    """
    Use a stubbed ContractAnalyzer that returns our honeypot snippet instead of
    calling the network. Ensures integration works end‑to‑end.
    """

    class StubAnalyzer(analyzer.ContractAnalyzer):
        def get_source_code(self, address: str):  # type: ignore
            return HONEYPOT_SNIPPET, True

    stub = StubAnalyzer(api_key="")
    report_data = stub.analyze_contract("0x1234567890abcdef1234567890abcdef12345678")
    assert report_data["risk"] == "HIGH"
    assert "modifiable_fee" in report_data["flags"]


def test_proxy_pattern_detection():
    """Ensure the proxy/delegatecall pattern is detected."""
    proxy_code = """
    // Simple delegatecall proxy example
    pragma solidity ^0.8.0;
    contract Proxy {
        address public implementation;
        function upgradeTo(address newImpl) external {
            implementation = newImpl;
        }
        fallback() external payable {
            (bool success, ) = implementation.delegatecall(msg.data);
            require(success);
        }
    }
    """
    flags = rules.run_all_checks(proxy_code, source_available=True)
    assert flags["proxy_pattern"]