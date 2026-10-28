// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Demonstrates EVM Stack Too Deep architectural limitation and its Struct / Memory packing mitigation.
contract StackTooDeepRefactor {
    // Problem in EVM: The EVM stack has a limit of 1024 elements, but more critically,
    // only the top 16 stack slots can be directly accessed via DUP1..DUP16 and SWAP1..SWAP16.
    // If a function defines or receives more than 16 local variables/parameters, the compiler throws:
    // "CompilerError: Stack too deep, try compiling with `--via-ir` (similarly can fail) or refactor."

    // MITIGATION: Encapsulate related parameters into structured types (Struct Packing)
    struct OrderParams {
        address maker;
        address taker;
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 minAmountOut;
        uint256 feeRate;
        uint256 deadline;
        uint256 nonce;
        bytes signature;
    }

    struct OrderResult {
        uint256 executedAmountIn;
        uint256 executedAmountOut;
        uint256 feeCharged;
        bool isSettled;
    }

    event OrderProcessed(bytes32 indexed orderHash, address maker, uint256 executedAmountOut);

    /// @notice Process order without stack overflow by passing struct memory pointers
    function processOrderStructured(OrderParams memory params)
        external
        returns (OrderResult memory result)
    {
        require(block.timestamp <= params.deadline, "Order expired");
        require(params.amountIn > 0, "Zero amount");

        bytes32 orderHash = keccak256(
            abi.encode(params.maker, params.nonce, params.amountIn, params.minAmountOut)
        );

        // Compute internal fee using helper (sub-scope reduces active stack frame)
        uint256 fee = _calculateFee(params.amountIn, params.feeRate);
        uint256 netAmountIn = params.amountIn - fee;

        result = OrderResult({
            executedAmountIn: netAmountIn,
            executedAmountOut: params.minAmountOut,
            feeCharged: fee,
            isSettled: true
        });

        emit OrderProcessed(orderHash, params.maker, result.executedAmountOut);
    }

    function _calculateFee(uint256 amount, uint256 feeRate) internal pure returns (uint256) {
        return (amount * feeRate) / 10_000;
    }
}
