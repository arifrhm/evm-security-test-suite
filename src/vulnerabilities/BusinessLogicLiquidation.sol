// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Demonstrates a Business Logic flaw where flawed health factor math allows premature liquidation.
contract VulnerableLendingPool {
    struct Position {
        uint256 collateralETH;
        uint256 debtUSD;
    }

    mapping(address => Position) public positions;
    uint256 public constant ETH_PRICE_USD = 2000; // $2,000 per ETH

    function depositCollateral() external payable {
        positions[msg.sender].collateralETH += msg.value;
    }

    function borrow(uint256 amountUSD) external {
        Position storage pos = positions[msg.sender];
        uint256 collateralUSD = (pos.collateralETH * ETH_PRICE_USD) / 1 ether;
        require(collateralUSD >= (amountUSD * 150) / 100, "Undercollateralized");
        pos.debtUSD += amountUSD;
    }

    /// @notice VULNERABILITY: Flawed liquidation threshold logic
    /// Instead of checking if collateral < 150% of debt, it allows liquidation whenever
    /// collateral <= debt * 2, liquidating completely healthy borrowers and transferring
    /// their collateral to the liquidator without repaying matching debt!
    function liquidateVulnerable(address borrower) external {
        Position storage pos = positions[borrower];
        uint256 collateralUSD = (pos.collateralETH * ETH_PRICE_USD) / 1 ether;

        // FLAW: Condition is inverted or excessively high (200% instead of < 110%)
        require(collateralUSD <= pos.debtUSD * 2, "Cannot liquidate");

        // FLAW 2: Liquidator gets ALL collateral without paying full debt
        uint256 rewardETH = pos.collateralETH;
        pos.collateralETH = 0;
        pos.debtUSD = 0;

        payable(msg.sender).transfer(rewardETH);
    }
}

/// @notice Secure lending pool with formal Health Factor (WAD 1e18) and strict Close Factor.
contract SecureLendingPool {
    error HealthyPosition(uint256 healthFactor);
    error ExceedsCloseFactor();
    error TransferFailed();

    struct Position {
        uint256 collateralETH;
        uint256 debtUSD; // 18 decimals
    }

    mapping(address => Position) public positions;
    uint256 public constant ETH_PRICE_USD = 2000e18; // $2,000 in 18 decimals
    uint256 public constant LIQUIDATION_THRESHOLD_BPS = 8000; // 80% (collateral must be at least 125% of debt)
    uint256 public constant LIQUIDATION_BONUS_BPS = 10500; // 5% bonus to liquidator
    uint256 public constant WAD = 1e18;

    function depositCollateral() external payable {
        positions[msg.sender].collateralETH += msg.value;
    }

    function borrow(uint256 amountUSD) external {
        Position storage pos = positions[msg.sender];
        pos.debtUSD += amountUSD;
        uint256 hf = getHealthFactor(msg.sender);
        require(hf >= WAD, "Health factor below 1.0");
    }

    /// @notice Calculates Health Factor: (CollateralValue * Threshold) / Debt
    /// If HF < 1.0 (1e18), position is eligible for liquidation.
    function getHealthFactor(address user) public view returns (uint256) {
        Position memory pos = positions[user];
        if (pos.debtUSD == 0) return type(uint256).max;

        uint256 collateralValUSD = (pos.collateralETH * ETH_PRICE_USD) / WAD;
        return (collateralValUSD * LIQUIDATION_THRESHOLD_BPS * WAD) / (pos.debtUSD * 10_000);
    }

    /// @notice MITIGATION: Liquidate strictly only when HF < 1.0, with debt repayment requirement
    function liquidate(address borrower, uint256 debtToRepay) external {
        uint256 hf = getHealthFactor(borrower);
        if (hf >= WAD) revert HealthyPosition(hf);

        Position storage pos = positions[borrower];
        // Enforce maximum 50% close factor per liquidation call
        if (debtToRepay > pos.debtUSD / 2) revert ExceedsCloseFactor();

        // Calculate collateral to seize with 5% liquidation bonus
        uint256 collateralToSeizeUSD = (debtToRepay * LIQUIDATION_BONUS_BPS) / 10_000;
        uint256 collateralToSeizeETH = (collateralToSeizeUSD * WAD) / ETH_PRICE_USD;

        require(pos.collateralETH >= collateralToSeizeETH, "Insufficient collateral");

        pos.debtUSD -= debtToRepay;
        pos.collateralETH -= collateralToSeizeETH;

        (bool success, ) = msg.sender.call{value: collateralToSeizeETH}("");
        if (!success) revert TransferFailed();
    }
}
