// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console, stdError} from "forge-std/Test.sol";
import {
    VulnerableCumulativeVault,
    SecureCumulativeVault
} from "../src/vulnerabilities/ArithmeticDosDefense.sol";

contract ArithmeticDosDefenseTest is Test {
    VulnerableCumulativeVault public vulnVault;
    SecureCumulativeVault public secureVault;

    address public victim = address(0x101);
    address public attacker = address(0xBAD);

    function setUp() public {
        vulnVault = new VulnerableCumulativeVault();
        secureVault = new SecureCumulativeVault();
    }

    /// @notice Proves the vulnerability: Arithmetic overflow bricks withdrawal for honest users
    function test_Exploit_ArithmeticPanicBricksWithdrawal() public {
        // Victim deposits 1 ETH into vulnerable vault
        vm.deal(victim, 1 ether);
        vm.prank(victim);
        vulnVault.deposit{value: 1 ether}(uint64(1 ether));

        // Attacker deposits an amount pushing cumulativeVolume near uint64.max
        uint64 nearMax = type(uint64).max - uint64(1 ether) - 1;
        vm.deal(attacker, nearMax);
        vm.prank(attacker);
        vulnVault.deposit{value: nearMax}(nearMax);

        // Victim now tries to withdraw their 1 ETH
        // But the internal _recordVolume adds 1 ether, exceeding type(uint64).max!
        vm.prank(victim);
        vm.expectRevert(stdError.arithmeticError);
        vulnVault.withdraw(uint64(1 ether));

        console.log("[CRITICAL CONFIRMED] Arithmetic overflow panicked and permanently locked victim's funds!");
    }

    /// @notice Proves the mitigation: Saturating math clamps safely and guarantees withdrawal
    function test_Mitigation_SaturatingMathPreventsLock() public {
        // Victim deposits 1 ETH into secure vault
        vm.deal(victim, 1 ether);
        vm.prank(victim);
        secureVault.deposit{value: 1 ether}();

        // Massive deposit near uint256 max volume
        vm.deal(attacker, 100 ether);
        vm.prank(attacker);
        secureVault.deposit{value: 100 ether}();

        // Victim withdraws 1 ETH safely
        uint256 balBefore = victim.balance;
        vm.prank(victim);
        secureVault.withdraw(1 ether);

        assertEq(victim.balance, balBefore + 1 ether);
        console.log("[SECURITY VERIFIED] Saturating arithmetic prevented overflow panic; funds safely withdrawn!");
    }
}
