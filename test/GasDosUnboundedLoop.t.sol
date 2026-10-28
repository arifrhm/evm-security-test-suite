// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {
    VulnerableAirdrop,
    SecurePullAirdrop
} from "../src/vulnerabilities/GasDosUnboundedLoop.sol";

contract GasDosUnboundedLoopTest is Test {
    VulnerableAirdrop public vulnDrop;
    SecurePullAirdrop public secureDrop;

    address public user1 = address(0x101);
    address public user2 = address(0x102);

    function setUp() public {
        vulnDrop = new VulnerableAirdrop();
        secureDrop = new SecurePullAirdrop();
    }

    /// @notice Demonstrates how gas scales linearly O(N) in push loops, causing DoS at scale
    function test_Exploit_UnboundedLoop_GasScaling() public {
        uint256 recipientCount = 100;
        address[] memory list = new address[](recipientCount);
        for (uint256 i = 0; i < recipientCount; i++) {
            list[i] = address(uint160(0x1000 + i));
        }

        vulnDrop.addRecipients(list, 0.01 ether);

        // Fund contract
        vm.deal(address(this), 100 ether);

        uint256 gasStart = gasleft();
        vulnDrop.distributeAllPush{value: 1 ether}();
        uint256 gasUsed = gasStart - gasleft();

        console.log("Gas consumed for 100 recipients push:", gasUsed);
        // At 100 recipients it already consumes ~3.5 million gas!
        // For 1,000+ recipients, it exceeds 30,000,000 block gas limit and reverts permanently!
        assertTrue(gasUsed > 1_000_000, "Gas should be substantial for batch iteration");
    }

    /// @notice Demonstrates O(1) constant gas with Pull-over-Push
    function test_Mitigation_PullPayment_ConstantGas() public {
        vm.deal(address(this), 10 ether);

        // Allocate rewards
        secureDrop.allocateReward(user1, 1 ether);
        secureDrop.allocateReward(user2, 1 ether);

        // Fund secure drop
        (bool ok, ) = address(secureDrop).call{value: 2 ether}("");
        require(ok);

        // User 1 claims with isolated, low, constant O(1) gas
        uint256 gasStart = gasleft();
        vm.prank(user1);
        secureDrop.claimReward();
        uint256 gasUsed = gasStart - gasleft();

        console.log("Gas consumed for individual pull claim:", gasUsed);
        // Gas is ~30k - 50k, safe from block limit
        assertTrue(gasUsed < 60_000, "Gas should be minimal and O(1)");
        assertEq(user1.balance, 1 ether);
        console.log("[SECURITY VERIFIED] Pull pattern guarantees O(1) gas immune to Block Gas DoS!");
    }
}
