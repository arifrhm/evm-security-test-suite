// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Mock Chainlink Aggregator interface
interface AggregatorV3Interface {
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
}

/// @notice AMM pool with spot price calculation vulnerable to flash loan manipulation.
contract VulnerableSpotAMM {
    uint256 public reserveETH;
    uint256 public reserveToken;

    constructor() {
        reserveETH = 100 ether;
        reserveToken = 100_000 ether; // 1 ETH = 1,000 Token
    }

    // Spot price query based on transient liquidity
    function getSpotPrice() public view returns (uint256) {
        return (reserveETH * 1e18) / reserveToken;
    }

    // Allows swapping, which heavily moves the spot price within a single block/tx
    function swap(uint256 tokenIn, bool isEthIn) external payable {
        if (isEthIn) {
            reserveETH += msg.value;
            uint256 tokenOut = (msg.value * reserveToken) / reserveETH;
            reserveToken -= tokenOut;
        } else {
            reserveToken += tokenIn;
            uint256 ethOut = (tokenIn * reserveETH) / reserveToken;
            reserveETH -= ethOut;
            payable(msg.sender).transfer(ethOut);
        }
    }
}

/// @notice Secure Oracle Consumer verifying Chainlink feed health & staleness.
contract SecureOracleConsumer {
    error StaleOraclePrice(uint256 updatedAt, uint256 currentTimestamp);
    error InvalidOracleAnswer(int256 answer);
    error IncompleteOracleRound(uint80 roundId, uint80 answeredInRound);

    AggregatorV3Interface public immutable priceFeed;
    uint256 public constant MAX_ORACLE_DELAY = 3 hours;

    constructor(address _priceFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    /// @notice Fetches latest validated price with comprehensive sanity checks
    function getValidatedPrice() public view returns (uint256) {
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        // CHECK 1: Ensure answer is strictly positive
        if (answer <= 0) revert InvalidOracleAnswer(answer);

        // CHECK 2: Prevent stale prices (Heartbeat check)
        if (updatedAt == 0 || block.timestamp - updatedAt > MAX_ORACLE_DELAY) {
            revert StaleOraclePrice(updatedAt, block.timestamp);
        }

        // CHECK 3: Ensure price belongs to completed round
        if (answeredInRound < roundId) {
            revert IncompleteOracleRound(roundId, answeredInRound);
        }

        return uint256(answer);
    }
}
