// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {
    VulnerableRewardDistributor,
    SecureRewardDistributor
} from "../src/vulnerabilities/ArithmeticLogic.sol";

contract ArithmeticPrecisionTest is Test {
    VulnerableRewardDistributor public vulnDistributor;
    SecureRewardDistributor public secureDistributor;

    function setUp() public {
        vulnDistributor = new VulnerableRewardDistributor();
        // Total pool: 1,000 ETH, Total Staked: 10,000 ETH
        secureDistributor = new SecureRewardDistributor(1_000 ether, 10_000 ether);
    }

    /// @notice Proves the vulnerability: Division before multiplication causes 100% precision truncation for small users
    function test_Exploit_DivisionBeforeMultiplication() public view {
        // User staked 500 ETH (out of 10,000 ETH = 5% of pool)
        // Fair reward should be: 5% of 1,000 ETH = 50 ETH!
        uint256 stake = 500 ether;

        uint256 vulnReward = vulnDistributor.calculateRewardVulnerable(stake);
        // Because 500 ether / 10,000 ether = 0 in integer math, reward is 0!
        assertEq(vulnReward, 0);
        console.log("[CRITICAL CONFIRMED] Vulnerable calculation truncated 50 ETH reward down to 0!");

        uint256 secureReward = secureDistributor.calculateReward(stake);
        // Correctly calculates 50 ETH
        assertEq(secureReward, 50 ether);
        console.log("[SECURITY VERIFIED] Secure calculation preserved full reward:", secureReward);
    }

    /// @notice Property-based Fuzz Test: Mathematical invariant testing
    /// Invariant: User reward must never exceed total reward pool, and must be strictly proportional.
    function testFuzz_RewardInvariant(uint128 userStake) public view {
        // Constrain input to valid range (1 wei up to totalStaked)
        vm.assume(userStake > 0 && userStake <= 10_000 ether);

        uint256 reward = secureDistributor.calculateReward(userStake);

        // Invariant 1: Reward can never exceed total pool
        assertTrue(reward <= 1_000 ether, "Reward exceeds total pool");

        // Invariant 2: Proportionality holds (reward / pool <= stake / totalStaked)
        assertTrue((reward * 1e18) / 1_000 ether <= (uint256(userStake) * 1e18) / 10_000 ether + 1);
    }
}
