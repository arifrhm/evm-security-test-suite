// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {
    VulnerableLendingPool,
    SecureLendingPool
} from "../src/vulnerabilities/BusinessLogicLiquidation.sol";

contract BusinessLogicLiquidationTest is Test {
    VulnerableLendingPool public vulnPool;
    SecureLendingPool public securePool;

    address public borrower = address(0x101);
    address public liquidator = address(0x202);

    function setUp() public {
        vulnPool = new VulnerableLendingPool();
        securePool = new SecureLendingPool();

        vm.deal(borrower, 20 ether);
        vm.deal(liquidator, 20 ether);
    }

    /// @notice Proves the vulnerability: Flawed liquidation logic seizes 100% collateral of a healthy user
    function test_Exploit_FlawedLiquidation_PrematureLiquidate() public {
        // Borrower deposits 1 ETH ($2,000) and borrows $1,000
        // Position is completely healthy (200% collateralized)!
        vm.startPrank(borrower);
        vulnPool.depositCollateral{value: 1 ether}();
        vulnPool.borrow(1000);
        vm.stopPrank();

        // Liquidator exploits flawed condition (collateralUSD <= debtUSD * 2)
        // Seizes all 1 ETH without repaying any debt!
        uint256 liquidatorBalBefore = liquidator.balance;
        vm.prank(liquidator);
        vulnPool.liquidateVulnerable(borrower);

        assertEq(liquidator.balance, liquidatorBalBefore + 1 ether);
        console.log("[CRITICAL CONFIRMED] Healthy borrower liquidated and robbed of 100% collateral due to business logic flaw!");
    }

    /// @notice Proves the mitigation: Healthy borrower cannot be liquidated (reverts with HealthyPosition error)
    function test_Mitigation_HealthyBorrowerProtected() public {
        // Borrower deposits 1 ETH ($2,000) and borrows $1,000
        vm.startPrank(borrower);
        securePool.depositCollateral{value: 1 ether}();
        securePool.borrow(1000e18);
        vm.stopPrank();

        // Health factor is: (2000 * 0.8) / 1000 = 1.6 (> 1.0 WAD)
        uint256 hf = securePool.getHealthFactor(borrower);
        assertTrue(hf >= 1e18, "Health factor should be healthy");

        // Liquidator attempts liquidation -> REVERTS
        vm.prank(liquidator);
        vm.expectRevert(
            abi.encodeWithSelector(
                SecureLendingPool.HealthyPosition.selector,
                hf
            )
        );
        securePool.liquidate(borrower, 500e18);

        console.log("[SECURITY VERIFIED] Healthy position protected by formal Health Factor invariant!");
    }
}
