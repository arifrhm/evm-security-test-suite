// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {
    VulnerableSpotAMM,
    SecureOracleConsumer,
    AggregatorV3Interface
} from "../src/vulnerabilities/OracleManipulation.sol";

/// @notice Controllable Mock Chainlink Aggregator for deterministic testing
contract MockChainlinkFeed is AggregatorV3Interface {
    uint80 public roundId = 1;
    int256 public answer = 2000e8; // $2,000 USD (8 decimals)
    uint256 public startedAt = 1000;
    uint256 public updatedAt = 1000;
    uint80 public answeredInRound = 1;

    function setMockData(
        uint80 _roundId,
        int256 _answer,
        uint256 _updatedAt,
        uint80 _answeredInRound
    ) external {
        roundId = _roundId;
        answer = _answer;
        updatedAt = _updatedAt;
        answeredInRound = _answeredInRound;
    }

    function latestRoundData()
        external
        view
        override
        returns (
            uint80,
            int256,
            uint256,
            uint256,
            uint80
        )
    {
        return (roundId, answer, startedAt, updatedAt, answeredInRound);
    }
}

contract OracleManipulationTest is Test {
    VulnerableSpotAMM public spotAmm;
    MockChainlinkFeed public mockFeed;
    SecureOracleConsumer public secureConsumer;

    address public attacker = address(0xBAD);

    function setUp() public {
        spotAmm = new VulnerableSpotAMM();
        mockFeed = new MockChainlinkFeed();
        secureConsumer = new SecureOracleConsumer(address(mockFeed));

        // Advance block time so timestamps are realistic
        vm.warp(2000);
        mockFeed.setMockData(1, 2000e8, block.timestamp, 1);
    }

    /// @notice Proves the vulnerability: Spot AMM price can be manipulated drastically in 1 transaction
    function test_Exploit_FlashLoanSpotOracleManipulation() public {
        uint256 spotBefore = spotAmm.getSpotPrice();
        console.log("Spot price before swap:", spotBefore);

        // Attacker simulates flash loan: swaps 200 ETH into pool
        vm.deal(attacker, 200 ether);
        vm.prank(attacker);
        spotAmm.swap{value: 200 ether}(0, true);

        uint256 spotAfter = spotAmm.getSpotPrice();
        console.log("Spot price after single-tx dump:", spotAfter);

        // Price shifted dramatically in the same block!
        assertTrue(spotAfter > spotBefore * 2);
        console.log("[CRITICAL CONFIRMED] Spot oracle easily skewed by single-transaction liquidity dump!");
    }

    /// @notice Proves the mitigation: Secure consumer accepts valid, fresh price
    function test_Mitigation_ValidChainlinkPrice() public {
        uint256 price = secureConsumer.getValidatedPrice();
        assertEq(price, 2000e8);
    }

    /// @notice Proves the mitigation: Rejects stale price data (heartbeat exceeded)
    function test_Mitigation_RevertOnStalePrice() public {
        // Warp time by 4 hours without oracle update (exceeds 3h threshold)
        vm.warp(block.timestamp + 4 hours);

        vm.expectRevert();
        secureConsumer.getValidatedPrice();
        console.log("[SECURITY VERIFIED] Stale oracle data successfully detected and rejected!");
    }

    /// @notice Proves the mitigation: Rejects negative or zero price
    function test_Mitigation_RevertOnNegativeOrZeroPrice() public {
        mockFeed.setMockData(2, -100, block.timestamp, 2);

        vm.expectRevert(
            abi.encodeWithSelector(
                SecureOracleConsumer.InvalidOracleAnswer.selector,
                -100
            )
        );
        secureConsumer.getValidatedPrice();
        console.log("[SECURITY VERIFIED] Zero/negative oracle answer reverted cleanly!");
    }

    /// @notice Proves the mitigation: Rejects incomplete round data
    function test_Mitigation_RevertOnIncompleteRound() public {
        mockFeed.setMockData(5, 2000e8, block.timestamp, 4); // answeredInRound (4) < roundId (5)

        vm.expectRevert(
            abi.encodeWithSelector(
                SecureOracleConsumer.IncompleteOracleRound.selector,
                5,
                4
            )
        );
        secureConsumer.getValidatedPrice();
        console.log("[SECURITY VERIFIED] Incomplete round detected and blocked!");
    }
}
