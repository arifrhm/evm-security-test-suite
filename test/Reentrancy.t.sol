// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {VulnerableVault, SecureVault, ReentrancyAttacker} from "../src/vulnerabilities/ReentrancyVault.sol";

contract ReentrancyTest is Test {
    VulnerableVault public vulnerableVault;
    SecureVault public secureVault;
    address public victim1 = address(0x101);
    address public victim2 = address(0x102);
    address public attackerUser = address(0xbad);

    function setUp() public {
        vulnerableVault = new VulnerableVault();
        secureVault = new SecureVault();

        // Seed vaults with victim liquidity
        vm.deal(victim1, 10 ether);
        vm.deal(victim2, 10 ether);

        vm.prank(victim1);
        vulnerableVault.deposit{value: 5 ether}();

        vm.prank(victim2);
        vulnerableVault.deposit{value: 5 ether}();

        vm.prank(victim1);
        secureVault.deposit{value: 5 ether}();

        vm.prank(victim2);
        secureVault.deposit{value: 5 ether}();
    }

    /// @notice Proves the vulnerability: Attacker drains 10 ETH from VulnerableVault with only 1 ETH
    function test_Exploit_VulnerableVault_Drained() public {
        assertEq(address(vulnerableVault).balance, 10 ether);

        vm.deal(attackerUser, 1 ether);
        vm.startPrank(attackerUser);

        ReentrancyAttacker attackerContract = new ReentrancyAttacker(address(vulnerableVault));
        attackerContract.attack{value: 1 ether}();

        vm.stopPrank();

        // Vault is completely drained to 0 ETH!
        assertEq(address(vulnerableVault).balance, 0 ether);
        // Attacker contract stole all 11 ETH (10 victim ETH + 1 initial ETH)
        assertEq(address(attackerContract).balance, 11 ether);
        console.log("[CRITICAL CONFIRMED] VulnerableVault drained! Attacker balance:", address(attackerContract).balance);
    }

    /// @notice Proves the mitigation: SecureVault reverts reentrancy attempt and preserves funds
    function test_Mitigation_SecureVault_ReentrancyBlocked() public {
        assertEq(address(secureVault).balance, 10 ether);

        vm.deal(attackerUser, 1 ether);
        vm.startPrank(attackerUser);

        // Attacker attempts the same exploit against SecureVault
        ReentrancyAttacker attackerContract = new ReentrancyAttacker(address(secureVault));

        // In SecureVault, the state is zeroed before transfer (CEI) AND protected by mutex
        // The second re-entrant call fails with ReentrancyGuardLocked() or NoBalance()
        vm.expectRevert();
        attackerContract.attack{value: 1 ether}();

        vm.stopPrank();

        // Vault funds remain safe and untouched
        assertEq(address(secureVault).balance, 10 ether);
        console.log("[SECURITY VERIFIED] SecureVault successfully blocked reentrancy attack!");
    }
}
