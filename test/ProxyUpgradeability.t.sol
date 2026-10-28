// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {
    MinimalProxy,
    LogicV1,
    LogicV2
} from "../src/vulnerabilities/ProxyUpgradeability.sol";

contract ProxyUpgradeabilityTest is Test {
    LogicV1 public logicV1;
    LogicV2 public logicV2;
    MinimalProxy public proxy;

    address public proxyAdmin = address(0xAA11);
    address public attacker = address(0xBAD);

    function setUp() public {
        logicV1 = new LogicV1();
        logicV2 = new LogicV2();

        // Deploy proxy pointing to LogicV1, managed by proxyAdmin
        proxy = new MinimalProxy(address(logicV1), proxyAdmin);
    }

    /// @notice Proves the mitigation for EVM Immutability limitation using proxy upgrade pattern
    function test_Mitigation_ProxyUpgrade_PreservesState() public {
        // Cast proxy address to LogicV1 interface
        LogicV1 proxiedV1 = LogicV1(address(proxy));

        // Initialize state via proxy
        proxiedV1.initialize(100);
        assertEq(proxiedV1.value(), 100);
        assertEq(proxiedV1.getVersion(), "V1");

        // Attacker attempts unauthorized upgrade -> REVERTS
        vm.prank(attacker);
        vm.expectRevert("Caller is not proxy admin");
        proxy.upgradeTo(address(logicV2));

        // Admin upgrades implementation to LogicV2
        vm.prank(proxyAdmin);
        proxy.upgradeTo(address(logicV2));

        // Cast proxy address to LogicV2 interface
        LogicV2 proxiedV2 = LogicV2(address(proxy));

        // Invariant 1: State value is fully preserved (address and storage persisted)
        assertEq(proxiedV2.value(), 100);
        assertEq(proxiedV2.getVersion(), "V2");

        // Invariant 2: New functionality is active
        proxiedV2.setMultiplier(5);
        assertEq(proxiedV2.getMultipliedValue(), 500);

        console.log("[ARCHITECTURAL VERIFIED] EVM Immutability mitigated: Contract patched seamlessly with 100% state retention!");
    }
}
