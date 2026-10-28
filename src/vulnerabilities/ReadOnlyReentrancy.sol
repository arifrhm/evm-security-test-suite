// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Vulnerable Curve-style LP pool where view function getVirtualPrice() can be read during reentrancy.
contract VulnerableLPPool {
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "ReentrancyGuard: locked");
        _locked = true;
        _;
        _locked = false;
    }

    function deposit() external payable nonReentrant {
        require(msg.value > 0, "Zero deposit");
        balances[msg.sender] += msg.value;
        totalShares += msg.value;
    }

    /// @notice Withdraws ETH and burns shares. Note that _locked protects this write function,
    /// but the external call happens BEFORE totalShares is burned or while balance is depleted!
    function withdraw(uint256 shares) external nonReentrant {
        require(balances[msg.sender] >= shares, "Insufficient balance");

        // VULNERABILITY: External call happens while pool reserves are distorted
        (bool success, ) = msg.sender.call{value: shares}("");
        require(success, "ETH transfer failed");

        balances[msg.sender] -= shares;
        totalShares -= shares;
    }

    /// @notice Read-only view function used by external lending protocols to price collateral!
    /// Because this is a view function, nonReentrant cannot be placed on it directly in normal Solidity,
    /// so external protocols read this distorted price mid-withdrawal.
    function getVirtualPrice() external view returns (uint256) {
        if (totalShares == 0) return 1 ether;
        // During withdraw(), address(this).balance is already reduced by `shares`,
        // but totalShares has NOT been decremented yet! Virtual price drops drastically!
        return (address(this).balance * 1 ether) / totalShares;
    }
}

/// @notice External Lending Protocol that relies on VulnerableLPPool to price collateral.
contract VulnerableLendingPlatform {
    VulnerableLPPool public lpPool;
    mapping(address => uint256) public userBorrowed;

    constructor(address _lpPool) {
        lpPool = VulnerableLPPool(_lpPool);
    }

    /// @notice Liquidates a borrower if their collateral valuation drops.
    /// VULNERABILITY: Reads read-only virtual price, which can be manipulated mid-transaction!
    function checkLiquidation(address user, uint256 collateralShares) external view returns (bool) {
        uint256 price = lpPool.getVirtualPrice();
        uint256 collateralValue = (collateralShares * price) / 1 ether;
        return collateralValue < userBorrowed[user];
    }
}

/// @notice Secure LP Pool implementing Read-Only Reentrancy protection via public reentrancy status.
contract SecureLPPool {
    error ReadOnlyReentrancyDetected();
    error ReentrancyGuardLocked();

    mapping(address => uint256) public balances;
    uint256 public totalShares;
    
    // Status: 1 = NOT_ENTERED, 2 = ENTERED
    uint256 private _status;

    modifier nonReentrant() {
        if (_status == 2) revert ReentrancyGuardLocked();
        _status = 2;
        _;
        _status = 1;
    }

    constructor() {
        _status = 1;
    }

    function isLocked() public view returns (bool) {
        return _status == 2;
    }

    function deposit() external payable nonReentrant {
        require(msg.value > 0, "Zero deposit");
        balances[msg.sender] += msg.value;
        totalShares += msg.value;
    }

    function withdraw(uint256 shares) external nonReentrant {
        require(balances[msg.sender] >= shares, "Insufficient balance");

        // MITIGATION: Strict CEI - update state BEFORE external call
        balances[msg.sender] -= shares;
        totalShares -= shares;

        (bool success, ) = msg.sender.call{value: shares}("");
        require(success, "ETH transfer failed");
    }

    /// @notice MITIGATION: View function actively checks if contract is currently executing a state transition!
    function getVirtualPrice() external view returns (uint256) {
        if (isLocked()) revert ReadOnlyReentrancyDetected();
        if (totalShares == 0) return 1 ether;
        return (address(this).balance * 1 ether) / totalShares;
    }
}
