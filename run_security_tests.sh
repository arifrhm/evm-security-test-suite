#!/usr/bin/env bash
set -euo pipefail

# EVM Security Testing & Mitigation Automated Runner
# Uses Foundry Forge to compile, trace, fuzz, and snapshot tests

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

FORGE_BIN="/root/.foundry/bin/forge"
if ! command -v "$FORGE_BIN" &> /dev/null; then
    FORGE_BIN="forge"
fi

echo "=================================================================="
echo "🛡️  EVM SMART CONTRACT SECURITY & ARCHITECTURE TEST HARNESS"
echo "=================================================================="
echo "Directory: $REPO_ROOT"
echo "Forge:     $($FORGE_BIN --version)"
echo "------------------------------------------------------------------"

echo ""
echo "▶ Running full test suite with traces (-vv)..."
"$FORGE_BIN" test -vv

echo ""
echo "▶ Generating gas consumption snapshots..."
"$FORGE_BIN" snapshot

echo ""
echo "=================================================================="
echo "✅ All 33 security tests, stateful invariants & mitigations PASSED!"
echo "=================================================================="
