// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {
    AdvancedOracleConsumer,
    IChainlinkAggregator,
    ISequencerUptimeFeed
} from "../src/vulnerabilities/AdvancedOracleDefense.sol";

contract MockAggregatorWithBounds is IChainlinkAggregator {
    uint80 public roundId = 1;
    int256 public answer = 2000e8;
    uint256 public startedAt = 1000;
    uint256 public updatedAt = 1000;
    uint80 public answeredInRound = 1;

    int256 public min = 100e8; // Floor: $100
    int256 public max = 100_000e8; // Ceiling: $100,000

    function setMock(int256 _answer, uint256 _updatedAt) external {
        answer = _answer;
        updatedAt = _updatedAt;
    }

    function latestRoundData()
        external
        view
        override
        returns (uint80, int256, uint256, uint256, uint80)
    {
        return (roundId, answer, startedAt, updatedAt, answeredInRound);
    }

    function minAnswer() external view override returns (int256) {
        return min;
    }

    function maxAnswer() external view override returns (int256) {
        return max;
    }
}

contract MockSequencerFeed is ISequencerUptimeFeed {
    int256 public status = 0; // 0 = UP, 1 = DOWN
    uint256 public restartTimestamp = 1000;

    function setStatus(int256 _status, uint256 _restartTimestamp) external {
        status = _status;
        restartTimestamp = _restartTimestamp;
    }

    function latestRoundData()
        external
        view
        override
        returns (uint80, int256, uint256, uint256, uint80)
    {
        return (1, status, restartTimestamp, block.timestamp, 1);
    }
}

contract AdvancedOracleDefenseTest is Test {
    MockAggregatorWithBounds public priceFeed;
    MockSequencerFeed public sequencerFeed;
    AdvancedOracleConsumer public consumer;

    function setUp() public {
        vm.warp(10_000);
        priceFeed = new MockAggregatorWithBounds();
        sequencerFeed = new MockSequencerFeed();

        // Initialize with sequencer UP since timestamp 5000 (grace period > 3600s satisfied)
        sequencerFeed.setStatus(0, 5000);
        priceFeed.setMock(2000e8, block.timestamp);

        consumer = new AdvancedOracleConsumer(address(priceFeed), address(sequencerFeed));
    }

    /// @notice Normal operational price retrieval
    function test_NormalOperation() public view {
        uint256 price = consumer.getHardenedPrice();
        assertEq(price, 2000e8);
    }

    /// @notice Proves L2 Sequencer downtime check reverts transactions
    function test_RevertWhenSequencerDown() public {
        // Sequencer goes down (answer = 1)
        sequencerFeed.setStatus(1, block.timestamp);

        vm.expectRevert(AdvancedOracleConsumer.L2SequencerDown.selector);
        consumer.getHardenedPrice();
        console.log("[SECURITY VERIFIED] L2 Sequencer outage detected and blocked!");
    }

    /// @notice Proves Grace Period enforcement after sequencer reboot
    function test_RevertDuringSequencerGracePeriod() public {
        // Sequencer just rebooted 10 minutes ago (600s < 3600s grace period)
        sequencerFeed.setStatus(0, block.timestamp - 600);

        vm.expectRevert(
            abi.encodeWithSelector(
                AdvancedOracleConsumer.L2SequencerGracePeriodActive.selector,
                600,
                3600
            )
        );
        consumer.getHardenedPrice();
        console.log("[SECURITY VERIFIED] Grace period protected against post-outage backlogged txs!");
    }

    /// @notice Proves minAnswer floor circuit breaker (preventing LUNA crash exploits)
    function test_RevertWhenMinAnswerFloorHit_LunaScenario() public {
        // Price crashes to the aggregator min floor of $100
        priceFeed.setMock(100e8, block.timestamp);

        vm.expectRevert(
            abi.encodeWithSelector(
                AdvancedOracleConsumer.CircuitBreakerMinMaxHit.selector,
                100e8,
                100e8,
                100_000e8
            )
        );
        consumer.getHardenedPrice();
        console.log("[SECURITY VERIFIED] minAnswer hard floor triggered circuit breaker, preventing bad debt exploit!");
    }
}
