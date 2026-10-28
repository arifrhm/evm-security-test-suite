// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Demonstrates precision loss from division before multiplication and integer truncation.
contract VulnerableRewardDistributor {
    uint256 public totalRewardPool;
    uint256 public totalStaked;

    constructor() {
        totalRewardPool = 1_000 ether;
        totalStaked = 10_000 ether;
    }

    /// @notice VULNERABILITY: Division before multiplication
    /// If userStake < totalStaked, (userStake / totalStaked) evaluates to 0!
    function calculateRewardVulnerable(uint256 userStake) external view returns (uint256) {
        // Integer division truncates to zero immediately
        uint256 userShare = userStake / totalStaked;
        return userShare * totalRewardPool;
    }
}

/// @notice Secure reward calculation with fixed-point scaling (WAD 1e18) and proper operation order.
contract SecureRewardDistributor {
    error ZeroTotalStaked();
    error ExceedsRewardPool();

    uint256 public totalRewardPool;
    uint256 public totalStaked;
    uint256 public constant SCALE = 1e18; // 18 decimal precision multiplier

    constructor(uint256 _rewardPool, uint256 _totalStaked) {
        totalRewardPool = _rewardPool;
        totalStaked = _totalStaked;
    }

    /// @notice MITIGATION: Multiplication before division + high-precision fixed point scaling
    function calculateReward(uint256 userStake) public view returns (uint256) {
        if (totalStaked == 0) revert ZeroTotalStaked();

        // Perform multiplication first to prevent truncation
        uint256 reward = (userStake * totalRewardPool) / totalStaked;
        return reward;
    }

    /// @notice High-precision share percentage calculation in Basis Points (1 bps = 0.01%)
    function calculateShareInBps(uint256 userStake) external view returns (uint256) {
        if (totalStaked == 0) revert ZeroTotalStaked();
        return (userStake * 10_000) / totalStaked;
    }
}
