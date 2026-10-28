// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {SecureVault} from "../../src/vulnerabilities/ReentrancyVault.sol";

/// @notice Handler for Foundry Stateful Invariant Fuzz Testing.
/// Manages randomized actors, bounded inputs, and tracks ghost state variables.
contract VaultHandler is Test {
    SecureVault public vault;

    address[] public actors;
    address internal currentActor;

    // Ghost variables tracking ground truth
    uint256 public ghost_totalDeposited;
    uint256 public ghost_totalWithdrawn;
    mapping(address => uint256) public ghost_userBalances;

    constructor(SecureVault _vault) {
        vault = _vault;

        // Initialize 3 realistic actors
        actors.push(address(0x1001));
        actors.push(address(0x1002));
        actors.push(address(0x1003));

        for (uint256 i = 0; i < actors.length; i++) {
            vm.deal(actors[i], 1_000 ether);
        }
    }

    modifier useActor(uint256 actorIndexSeed) {
        currentActor = actors[actorIndexSeed % actors.length];
        vm.startPrank(currentActor);
        _;
        vm.stopPrank();
    }

    function deposit(uint256 actorSeed, uint256 amount) external useActor(actorSeed) {
        // Bound deposit amount between 1 wei and 10 ETH
        amount = bound(amount, 1, 10 ether);

        vault.deposit{value: amount}();

        ghost_totalDeposited += amount;
        ghost_userBalances[currentActor] += amount;
    }

    function withdraw(uint256 actorSeed) external useActor(actorSeed) {
        uint256 userBalance = vault.balances(currentActor);
        if (userBalance == 0) return;

        vault.withdraw();

        ghost_totalWithdrawn += userBalance;
        ghost_userBalances[currentActor] = 0;
    }

    function ghost_netDeposits() external view returns (uint256) {
        return ghost_totalDeposited - ghost_totalWithdrawn;
    }

    function getActorsCount() external view returns (uint256) {
        return actors.length;
    }
}
