// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {SecureVault} from "../../src/vulnerabilities/ReentrancyVault.sol";
import {VaultHandler} from "./VaultHandler.sol";

/// @notice Foundry Stateful Invariant Fuzz Testing Suite.
/// Runs thousands of pseudo-random call sequences across multiple actors to break core protocol invariants.
contract VaultInvariantTest is Test {
    SecureVault public vault;
    VaultHandler public handler;

    function setUp() public {
        vault = new SecureVault();
        handler = new VaultHandler(vault);

        // Instruct Forge invariant fuzzer to target the handler
        targetContract(address(handler));
    }

    /// @notice Core Protocol Invariant 1: Vault Solvency
    /// The physical balance of the vault must ALWAYS exactly match total net ghost deposits.
    function invariant_VaultSolvency() public view {
        uint256 expectedBalance = handler.ghost_netDeposits();
        uint256 actualBalance = address(vault).balance;

        assertEq(actualBalance, expectedBalance, "INVARIANT VIOLATED: Vault physical balance drifted from net deposits!");
    }

    /// @notice Core Protocol Invariant 2: Individual Balances Integrity
    /// The vault's recorded balance for every actor must match the handler's ghost tracking.
    function invariant_IndividualBalancesIntegrity() public view {
        uint256 actorsCount = handler.getActorsCount();
        for (uint256 i = 0; i < actorsCount; i++) {
            address actor = handler.actors(i);
            assertEq(
                vault.balances(actor),
                handler.ghost_userBalances(actor),
                "INVARIANT VIOLATED: User balance in vault desynchronized from ghost ledger!"
            );
        }
    }
}
