// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Demonstrates Denial-of-Service (DoS) vulnerability via unbounded loop hitting block gas limits.
contract VulnerableAirdrop {
    address[] public recipients;
    mapping(address => uint256) public amounts;

    function addRecipients(address[] calldata newRecipients, uint256 defaultAmount) external {
        for (uint256 i = 0; i < newRecipients.length; i++) {
            recipients.push(newRecipients[i]);
            amounts[newRecipients[i]] = defaultAmount;
        }
    }

    /// @notice VULNERABILITY: Unbounded loop across all recipients in a single transaction.
    /// As the array grows, gas needed exceeds block gas limit (30M gas), permanently bricking this function!
    function distributeAllPush() external payable {
        for (uint256 i = 0; i < recipients.length; i++) {
            address recipient = recipients[i];
            uint256 amount = amounts[recipient];
            if (amount > 0) {
                amounts[recipient] = 0;
                // Costly storage mutation + call inside loop
                (bool success, ) = recipient.call{value: amount}("");
                require(success, "Push failed");
            }
        }
    }

    function getRecipientsCount() external view returns (uint256) {
        return recipients.length;
    }
}

/// @notice Secure reward distributor using Pull-over-Push pattern with O(1) constant gas per claim.
contract SecurePullAirdrop {
    error ZeroClaimAmount();
    error TransferFailed();

    mapping(address => uint256) public claimableAmounts;

    event RewardClaimed(address indexed recipient, uint256 amount);
    event RewardAllocated(address indexed recipient, uint256 amount);

    function allocateReward(address recipient, uint256 amount) external {
        claimableAmounts[recipient] += amount;
        emit RewardAllocated(recipient, amount);
    }

    /// @notice MITIGATION: Each user pulls their own reward in an isolated O(1) transaction.
    /// Unbounded array loops are completely eliminated.
    function claimReward() external {
        uint256 amount = claimableAmounts[msg.sender];
        if (amount == 0) revert ZeroClaimAmount();

        // CEI Pattern
        claimableAmounts[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert TransferFailed();

        emit RewardClaimed(msg.sender, amount);
    }

    receive() external payable {}
}
