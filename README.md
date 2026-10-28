# 🛡️ EVM Smart Contract Security & Architecture Test Suite

A comprehensive, production-grade test suite built with **Foundry (Forge)** designed to empirically demonstrate smart contract vulnerabilities (**Red-Team Attack Replication**), verify robust defensive patterns (**Blue-Team Verification**), and stress-test protocols with **Stateful Invariant Fuzzing**.

---

## 📂 Vulnerability & Architecture Mapping Matrix

| Category | Vulnerable & Mitigation Contracts (`src/`) | Foundry Test Suite (`test/`) | Attack Vector & Defensive Mitigation |
| :--- | :--- | :--- | :--- |
| **1. Reentrancy (Single-Contract)** | [`ReentrancyVault.sol`](src/vulnerabilities/ReentrancyVault.sol) | [`Reentrancy.t.sol`](test/Reentrancy.t.sol) | **CEI (Checks-Effects-Interactions)** + Mutex `nonReentrant` lock. Malicious contracts attempting recursive callback in `receive()` are reverted. |
| **2. Read-Only & Cross-Contract Reentrancy** | [`ReadOnlyReentrancy.sol`](src/vulnerabilities/ReadOnlyReentrancy.sol) | [`ReadOnlyReentrancy.t.sol`](test/ReadOnlyReentrancy.t.sol) | Defends against Curve/Euler-style exploits where view functions (`getVirtualPrice()`) are queried mid-withdrawal. View functions actively enforce `isLocked()` checks. |
| **3. Unchecked External Calls** | [`UncheckedExternalCall.sol`](src/vulnerabilities/UncheckedExternalCall.sol) | [`UncheckedExternalCall.t.sol`](test/UncheckedExternalCall.t.sol) | **Pull-over-Push (Withdrawal Pattern)** & explicit boolean return validation (`require(success)`). Prevents silent transfer failures when interacting with contracts rejecting ETH. |
| **4. Access Control & Phishing** | [`AccessControlManager.sol`](src/vulnerabilities/AccessControlManager.sol) | [`AccessControl.t.sol`](test/AccessControl.t.sol) | **`Ownable2Step`** (safe pending-owner acceptance) and elimination of vulnerable `tx.origin` checks (stopping proxy/intermediate phishing). |
| **5. Oracle Manipulation & Flash Loans** | [`OracleManipulation.sol`](src/vulnerabilities/OracleManipulation.sol) | [`OracleManipulation.t.sol`](test/OracleManipulation.t.sol) | **Decentralized Chainlink Aggregator validation**: Heartbeat staleness checks, positive price bounds (`answer > 0`), and round completeness validation. |
| **6. Advanced Oracle & L2 Defenses** | [`AdvancedOracleDefense.sol`](src/vulnerabilities/AdvancedOracleDefense.sol) | [`AdvancedOracleDefense.t.sol`](test/AdvancedOracleDefense.t.sol) | **Chainlink `minAnswer`/`maxAnswer` floor circuit breaker** (preventing LUNA-style undercollateralized debt) and **L2 Sequencer Uptime Feed** with mandatory 1-hour grace period enforcement. |
| **7. Arithmetic & Precision Loss** | [`ArithmeticLogic.sol`](src/vulnerabilities/ArithmeticLogic.sol) | [`ArithmeticPrecision.t.sol`](test/ArithmeticPrecision.t.sol) | **Multiplication before division** with high-precision fixed-point scaling (WAD `1e18`) + Property-Based Fuzz Testing (256 randomized runs). |
| **8. Arithmetic Panic DoS Resilience** | [`ArithmeticDosDefense.sol`](src/vulnerabilities/ArithmeticDosDefense.sol) | [`ArithmeticDosDefense.t.sol`](test/ArithmeticDosDefense.t.sol) | Defends against Solidity 0.8+ overflow panic bricks where accumulator overflow locks honest withdrawals forever. Uses saturating math and decoupled principal safety. |
| **9. Business Logic & Liquidation Flaws** | [`BusinessLogicLiquidation.sol`](src/vulnerabilities/BusinessLogicLiquidation.sol) | [`BusinessLogicLiquidation.t.sol`](test/BusinessLogicLiquidation.t.sol) | **Formal Health Factor invariant ($HF \ge 1.0$)** & strict 50% Close Factor cap. Prevents premature liquidations and bad debt exploits. |
| **10. Gas Limits & Unbounded Loops** | [`GasDosUnboundedLoop.sol`](src/vulnerabilities/GasDosUnboundedLoop.sol) | [`GasDosUnboundedLoop.t.sol`](test/GasDosUnboundedLoop.t.sol) | **Isolated $\mathcal{O}(1)$ gas via Pull payment claims** (~36k gas). Eliminates massive array batching loops that risk crossing Ethereum's 30M Block Gas Limit. |
| **11. EVM Immutability (Basic Proxy)** | [`ProxyUpgradeability.sol`](src/vulnerabilities/ProxyUpgradeability.sol) | [`ProxyUpgradeability.t.sol`](test/ProxyUpgradeability.t.sol) | **ERC-1967 Upgradeable Proxy Pattern**. Allows logic patching while preserving 100% of contract state. |
| **12. Advanced Proxy & Namespaced Storage** | [`AdvancedProxySafety.sol`](src/vulnerabilities/AdvancedProxySafety.sol) | [`AdvancedProxySafety.t.sol`](test/AdvancedProxySafety.t.sol) | **Constructor initializer locks** (`initialized = true` on logic contract bytecode) + **ERC-7201: Namespaced Storage Layout** to mathematically prevent storage collisions across upgrades. |
| **13. Stack Too Deep & Memory Limits** | [`StackTooDeepRefactor.sol`](src/vulnerabilities/StackTooDeepRefactor.sol) | [`StackTooDeep.t.sol`](test/StackTooDeep.t.sol) | **Struct & Memory pointer packing** and helper sub-scoping to stay within the EVM 16-element stack access window (`DUP1..16` / `SWAP1..16`). |
| **14. Stateful Invariant Fuzzing** | [`ReentrancyVault.sol`](src/vulnerabilities/ReentrancyVault.sol) | [`VaultInvariant.t.sol`](test/invariants/VaultInvariant.t.sol) | **Stateful multi-actor invariant fuzzing** (2,048 random state transitions across 64 runs) verifying protocol solvency and individual balance invariants. |

---

## ⚡ Quick Start & Execution

Ensure you are inside the test suite directory:

```bash
cd /root/.gemini/antigravity-cli/scratch/evm-security-test-suite
```

### 1. Run All 33 Tests with Traces & Gas Profiling
Executes all unit, fuzz, and stateful invariant suites:

```bash
./run_security_tests.sh
```

Or invoke Forge directly:

```bash
/root/.foundry/bin/forge test -vv
```

### 2. Targeted Security Suites

- **Read-Only Reentrancy & Cross-Contract attack:**
  ```bash
  /root/.foundry/bin/forge test --match-contract ReadOnlyReentrancyTest -vvv
  ```

- **Advanced Chainlink bounds & L2 Sequencer outages:**
  ```bash
  /root/.foundry/bin/forge test --match-contract AdvancedOracleDefenseTest -vvv
  ```

- **Arithmetic Panic DoS Resilience:**
  ```bash
  /root/.foundry/bin/forge test --match-contract ArithmeticDosDefenseTest -vvv
  ```

- **Advanced Proxy Initializer lock & ERC-7201 storage:**
  ```bash
  /root/.foundry/bin/forge test --match-contract AdvancedProxySafetyTest -vvv
  ```

- **Stateful Invariant Fuzz Testing (2,048 random call sequences):**
  ```bash
  /root/.foundry/bin/forge test --match-contract VaultInvariantTest -vv
  ```

---

## 🛡️ Production Security Architecture Checklist

1. **Read-Only Views:** Always guard price-reporting views against mid-execution queries if balances or virtual prices can transiently skew.
2. **Oracle Circuit Breakers:** Never trust Chainlink `minAnswer` floors during market crashes; enforce explicit range bounds and integrate L2 Sequencer Uptime feeds with grace periods.
3. **Decoupled Math:** Never let peripheral statistics/rewards panicking with integer overflow block the principal capital withdrawal path.
4. **Proxy Hardening:** Always lock logic contract initializers in constructors and adopt **ERC-7201 Namespaced Storage** to eliminate storage collision bugs.
5. **Stateful Invariant Testing:** Complement stateless unit tests with Handler-based invariant fuzzers running thousands of random actor permutations.
