// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Demonstrates Arithmetic Denial-of-Service where an overflow reverts all future withdrawals.
contract VulnerableCumulativeVault {
    mapping(address => uint256) public balances;
    // Flawed choice of packed small integer accumulator prone to overflow
    uint64 public cumulativeVolume;
    uint256 public totalDeposits;

    function deposit(uint64 amount) external payable {
        require(msg.value == amount, "Value mismatch");
        balances[msg.sender] += amount;
        totalDeposits += amount;

        // VULNERABILITY: Uncapped accumulator. When cumulativeVolume exceeds type(uint64).max,
        // it triggers a Solidity 0.8+ panic revert on EVERY interaction!
        cumulativeVolume += amount;
    }

    /// @notice Withdraw requires updating cumulative stats before paying out.
    /// If cumulativeVolume is pushed near max, this function reverts permanently!
    function withdraw(uint64 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Coupled stat update that can panic
        _recordVolume(amount);

        balances[msg.sender] -= amount;
        totalDeposits -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function _recordVolume(uint64 amount) internal {
        cumulativeVolume += amount; // Panics on overflow!
    }
}

/// @notice Secure cumulative vault with saturating math and isolated principal withdrawals.
contract SecureCumulativeVault {
    error InsufficientBalance();
    error TransferFailed();

    mapping(address => uint256) public balances;
    uint256 public cumulativeVolume;
    uint256 public totalDeposits;

    function deposit() external payable {
        require(msg.value > 0, "Zero deposit");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;

        // MITIGATION 1: Saturating addition prevents arithmetic overflow panic
        cumulativeVolume = _saturatingAdd(cumulativeVolume, msg.value);
    }

    /// @notice MITIGATION 2: Principal withdrawal decoupled from accumulator failure
    function withdraw(uint256 amount) external {
        if (balances[msg.sender] < amount) revert InsufficientBalance();

        // CEI: Update state first
        balances[msg.sender] -= amount;
        totalDeposits -= amount;

        // Safely record stat without risking revert
        cumulativeVolume = _saturatingAdd(cumulativeVolume, amount);

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert TransferFailed();
    }

    function _saturatingAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            uint256 c = a + b;
            if (c < a) return type(uint256).max; // Clamp at max rather than reverting
            return c;
        }
    }
}
