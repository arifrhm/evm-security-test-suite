// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {StackTooDeepRefactor} from "../src/vulnerabilities/StackTooDeepRefactor.sol";

contract StackTooDeepTest is Test {
    StackTooDeepRefactor public refactorContract;

    function setUp() public {
        refactorContract = new StackTooDeepRefactor();
    }

    /// @notice Tests execution of structured order processing without EVM stack overflow
    function test_Execution_StructMemoryPacking() public {
        StackTooDeepRefactor.OrderParams memory params = StackTooDeepRefactor.OrderParams({
            maker: address(0xAAA),
            taker: address(0xBBB),
            tokenIn: address(0x1),
            tokenOut: address(0x2),
            amountIn: 10_000,
            minAmountOut: 9_900,
            feeRate: 50, // 0.5%
            deadline: block.timestamp + 1 hours,
            nonce: 1,
            signature: hex"12345678"
        });

        StackTooDeepRefactor.OrderResult memory result = refactorContract.processOrderStructured(params);

        // 10_000 * 50 / 10_000 = 50 fee
        assertEq(result.feeCharged, 50);
        assertEq(result.executedAmountIn, 9_950);
        assertEq(result.executedAmountOut, 9_900);
        assertTrue(result.isSettled);

        console.log("[ARCHITECTURAL VERIFIED] Struct packing passed 10+ variables through EVM stack flawlessly!");
    }
}
