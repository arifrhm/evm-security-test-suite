// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {
    VulnerableImplementation,
    SecureImplementation
} from "../src/vulnerabilities/AdvancedProxySafety.sol";
import {MinimalProxy} from "../src/vulnerabilities/ProxyUpgradeability.sol";

contract AdvancedProxySafetyTest is Test {
    VulnerableImplementation public vulnImpl;
    SecureImplementation public secureImpl;

    address public attacker = address(0xBAD);
    address public proxyAdmin = address(0xAA11);
    address public honestOwner = address(0x9999);

    function setUp() public {
        vulnImpl = new VulnerableImplementation();
        secureImpl = new SecureImplementation();
    }

    /// @notice Proves the vulnerability: Unlocked logic contract can be initialized directly by an attacker
    function test_Exploit_VulnerableImplementationInitializedDirectly() public {
        assertEq(vulnImpl.owner(), address(0));

        // Attacker initializes implementation contract directly
        vm.prank(attacker);
        vulnImpl.initialize(attacker);

        assertEq(vulnImpl.owner(), attacker);
        console.log("[CRITICAL CONFIRMED] Attacker directly took ownership of uninitialized logic contract!");
    }

    /// @notice Proves the mitigation: Constructor lock blocks direct logic contract initialization
    function test_Mitigation_SecureImplementationLockedAgainstDirectInit() public {
        // Implementation itself is already marked initialized in constructor
        assertTrue(secureImpl.isInitialized());

        // Attacker attempts direct initialization -> REVERTS
        vm.prank(attacker);
        vm.expectRevert(SecureImplementation.AlreadyInitialized.selector);
        secureImpl.initializeProxy(attacker, 100 ether);

        console.log("[SECURITY VERIFIED] Direct logic initialization blocked by constructor lock!");
    }

    /// @notice Proves the mitigation: ERC-7201 Namespaced Storage functions correctly through proxy
    function test_Mitigation_ProxyWithERC7201NamespacedStorage() public {
        // Deploy proxy delegating to secureImpl
        MinimalProxy proxy = new MinimalProxy(address(secureImpl), proxyAdmin);
        SecureImplementation proxied = SecureImplementation(address(proxy));

        // Initialize state via proxy
        proxied.initializeProxy(honestOwner, 500 ether);

        assertEq(proxied.getOwner(), honestOwner);
        assertEq(proxied.getDepositLimit(), 500 ether);
        assertTrue(proxied.isInitialized());

        console.log("[SECURITY VERIFIED] ERC-7201 Namespaced storage operating flawlessly via proxy!");
    }
}
