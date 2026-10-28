// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Vulnerable contract with missing or flawed access control (tx.origin phishing).
contract VulnerableVaultAdmin {
    address public owner;
    uint256 public protocolFee;

    constructor() {
        owner = msg.sender;
        protocolFee = 100; // 1%
    }

    // VULNERABILITY 1: Missing access control modifier entirely!
    function setProtocolFeeUnprotected(uint256 newFee) external {
        protocolFee = newFee;
    }

    // VULNERABILITY 2: Dangerous tx.origin check (vulnerable to phishing via malicious intermediate contract)
    function setOwnerPhishable(address newOwner) external {
        require(tx.origin == owner, "Not owner via tx.origin");
        owner = newOwner;
    }
}

/// @notice Secure contract implementing Ownable2Step & custom errors.
contract SecureVaultAdmin {
    error UnauthorizedCaller(address caller);
    error ZeroAddress();
    error NotPendingOwner();

    address public owner;
    address public pendingOwner;
    uint256 public protocolFee;

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event ProtocolFeeUpdated(uint256 oldFee, uint256 newFee);

    modifier onlyOwner() {
        if (msg.sender != owner) revert UnauthorizedCaller(msg.sender);
        _;
    }

    constructor() {
        owner = msg.sender;
        protocolFee = 100;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    function setProtocolFee(uint256 newFee) external onlyOwner {
        require(newFee <= 1000, "Fee cannot exceed 10%");
        emit ProtocolFeeUpdated(protocolFee, newFee);
        protocolFee = newFee;
    }

    // MITIGATION: 2-Step Ownership Transfer Pattern
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }
}
