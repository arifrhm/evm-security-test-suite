// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Interface for Chainlink Aggregator with min/max bounds
interface IChainlinkAggregator {
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );

    function minAnswer() external view returns (int256);
    function maxAnswer() external view returns (int256);
}

/// @notice Interface for Chainlink L2 Sequencer Uptime Feed
interface ISequencerUptimeFeed {
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer, // 0 = UP, 1 = DOWN
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}

/// @notice Production-grade Oracle consumer defending against minAnswer clamp and L2 sequencer outages.
contract AdvancedOracleConsumer {
    error L2SequencerDown();
    error L2SequencerGracePeriodActive(uint256 timeSinceRestart, uint256 requiredGracePeriod);
    error CircuitBreakerMinMaxHit(int256 answer, int256 minLimit, int256 maxLimit);
    error StalePrice(uint256 updatedAt, uint256 currentTimestamp);
    error InvalidPrice(int256 answer);
    error IncompleteRound(uint80 roundId, uint80 answeredInRound);

    IChainlinkAggregator public immutable priceFeed;
    ISequencerUptimeFeed public immutable sequencerUptimeFeed;

    uint256 public constant GRACE_PERIOD_TIME = 3600; // 1 hour grace period after sequencer restart
    uint256 public constant MAX_STALENESS = 3 hours;

    constructor(address _priceFeed, address _sequencerUptimeFeed) {
        priceFeed = IChainlinkAggregator(_priceFeed);
        sequencerUptimeFeed = ISequencerUptimeFeed(_sequencerUptimeFeed);
    }

    /// @notice Validates L2 Sequencer status before allowing any price queries
    function checkSequencer() public view {
        if (address(sequencerUptimeFeed) == address(0)) return; // Skipped on L1

        (
            ,
            int256 answer,
            uint256 startedAt,
            ,
            
        ) = sequencerUptimeFeed.latestRoundData();

        // Answer == 1 means Sequencer is DOWN
        if (answer == 1) revert L2SequencerDown();

        // Sequencer just restarted: enforce grace period
        uint256 timeSinceUp = block.timestamp - startedAt;
        if (timeSinceUp < GRACE_PERIOD_TIME) {
            revert L2SequencerGracePeriodActive(timeSinceUp, GRACE_PERIOD_TIME);
        }
    }

    /// @notice Fetches robust, validated price with min/max bounds and sequencer safety
    function getHardenedPrice() external view returns (uint256) {
        // Step 1: Ensure L2 Sequencer is fully operational and grace period passed
        checkSequencer();

        // Step 2: Query Price Feed
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        if (answer <= 0) revert InvalidPrice(answer);
        if (updatedAt == 0 || block.timestamp - updatedAt > MAX_STALENESS) {
            revert StalePrice(updatedAt, block.timestamp);
        }
        if (answeredInRound < roundId) revert IncompleteRound(roundId, answeredInRound);

        // Step 3: Check minAnswer and maxAnswer circuit breaker bounds
        int256 minLimit = priceFeed.minAnswer();
        int256 maxLimit = priceFeed.maxAnswer();

        // If the price hit the hardcoded aggregator floor or ceiling, the true market price
        // might be significantly worse (e.g. LUNA crash). Revert rather than trusting false floor!
        if (answer <= minLimit || answer >= maxLimit) {
            revert CircuitBreakerMinMaxHit(answer, minLimit, maxLimit);
        }

        return uint256(answer);
    }
}
