// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {
    VulnerableAuction,
    SecureAuction,
    MaliciousRejector
} from "../src/vulnerabilities/UncheckedExternalCall.sol";

contract UncheckedExternalCallTest is Test {
    VulnerableAuction public vulnAuction;
    SecureAuction public secureAuction;
    MaliciousRejector public rejector;

    address public honestBidder = address(0x111);
    address public maliciousUser = address(0x222);

    function setUp() public {
        vulnAuction = new VulnerableAuction();
        secureAuction = new SecureAuction();
        rejector = new MaliciousRejector();

        vm.deal(honestBidder, 10 ether);
        vm.deal(maliciousUser, 10 ether);
    }

    /// @notice Proves the vulnerability: Unchecked send() fails silently when bidder rejects ETH
    function test_Exploit_VulnerableAuction_SilentFailure() public {
        // Step 1: Rejector contract becomes highest bidder with 1 ETH
        vm.prank(maliciousUser);
        rejector.attackBid{value: 1 ether}(address(vulnAuction));
        assertEq(vulnAuction.highestBidder(), address(rejector));
        assertEq(vulnAuction.highestBid(), 1 ether);

        // Step 2: Honest bidder outbids with 2 ETH
        // The contract executes `payable(highestBidder).send(highestBid)`
        // Because rejector has no receive()/reverts, send() returns false.
        // But VulnerableAuction never checks the return value!
        vm.prank(honestBidder);
        vulnAuction.bid{value: 2 ether}();

        // New highest bidder updated despite previous bidder never receiving their 1 ETH refund
        assertEq(vulnAuction.highestBidder(), honestBidder);
        assertEq(vulnAuction.highestBid(), 2 ether);

        // Rejector contract balance is still 0 (refund lost/locked in auction contract!)
        assertEq(address(rejector).balance, 0 ether);
        console.log("[CRITICAL CONFIRMED] Send failed silently without revert. Prior bidder lost funds!");
    }

    /// @notice Proves the mitigation: Pull-over-push allows seamless auction progress and safe individual claims
    function test_Mitigation_SecureAuction_PullPattern() public {
        // Step 1: User bids 1 ETH
        vm.prank(honestBidder);
        secureAuction.bid{value: 1 ether}();
        assertEq(secureAuction.highestBidder(), honestBidder);

        // Step 2: Malicious user outbids with 2 ETH
        vm.prank(maliciousUser);
        secureAuction.bid{value: 2 ether}();

        // Step 3: Honest bidder's pending refund is credited safely without immediate push
        assertEq(secureAuction.pendingReturns(honestBidder), 1 ether);

        // Step 4: Honest bidder pulls their refund
        uint256 balBefore = honestBidder.balance;
        vm.prank(honestBidder);
        secureAuction.withdrawRefund();
        assertEq(honestBidder.balance, balBefore + 1 ether);
        assertEq(secureAuction.pendingReturns(honestBidder), 0 ether);

        console.log("[SECURITY VERIFIED] Pull-over-Push pattern isolated execution and refunded safely!");
    }
}
