// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Vulnerable auction that ignores external call return values and uses push payment.
contract VulnerableAuction {
    address public highestBidder;
    uint256 public highestBid;

    event HighestBidIncreased(address bidder, uint256 amount);

    function bid() external payable {
        require(msg.value > highestBid, "Bid too low");

        if (highestBidder != address(0)) {
            // VULNERABILITY 1: Unchecked low-level call return value.
            // If the previous bidder is a contract rejecting ETH, send() returns false,
            // but the transaction still proceeds and old highestBidder loses funds!
            payable(highestBidder).send(highestBid);
        }

        highestBidder = msg.sender;
        highestBid = msg.value;
        emit HighestBidIncreased(msg.sender, msg.value);
    }
}

/// @notice Secure auction implementing Pull-over-Push payment and checked calls.
contract SecureAuction {
    error BidTooLow();
    error NoRefundAvailable();
    error TransferFailed();

    address public highestBidder;
    uint256 public highestBid;

    // MITIGATION 1: Pull-over-Push pattern (Withdrawal pattern)
    // Avoids external calls during state-critical functions like bid()
    mapping(address => uint256) public pendingReturns;

    event HighestBidIncreased(address bidder, uint256 amount);
    event RefundWithdrawn(address recipient, uint256 amount);

    function bid() external payable {
        if (msg.value <= highestBid) revert BidTooLow();

        if (highestBidder != address(0)) {
            // Credit previous bidder instead of direct push transfer
            pendingReturns[highestBidder] += highestBid;
        }

        highestBidder = msg.sender;
        highestBid = msg.value;
        emit HighestBidIncreased(msg.sender, msg.value);
    }

    function withdrawRefund() external {
        uint256 amount = pendingReturns[msg.sender];
        if (amount == 0) revert NoRefundAvailable();

        // CEI: reset state before external call
        pendingReturns[msg.sender] = 0;

        // MITIGATION 2: Explicitly checked external call
        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert TransferFailed();

        emit RefundWithdrawn(msg.sender, amount);
    }
}

/// @notice Malicious contract designed to reject incoming ETH and induce failure.
contract MaliciousRejector {
    function attackBid(address auction) external payable {
        (bool success, ) = auction.call{value: msg.value}(abi.encodeWithSignature("bid()"));
        require(success, "Bid failed");
    }

    // Explicitly reject ETH transfers
    receive() external payable {
        revert("Rejecting ETH");
    }
}
