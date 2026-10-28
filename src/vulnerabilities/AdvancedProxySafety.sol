// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Vulnerable implementation leaving constructor uninitialized
contract VulnerableImplementation {
    address public owner;
    bool public initialized;

    // VULNERABILITY: No constructor disabling initializers on implementation!
    // An attacker can call initialize() directly on this logic address (outside of proxy).
    function initialize(address _owner) external {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
    }
}

/// @notice Secure implementation enforcing constructor lock and ERC-7201 Namespaced Storage
contract SecureImplementation {
    error InitializersAlreadyDisabled();
    error Unauthorized();
    error AlreadyInitialized();

    // ERC-7201: keccak256(abi.encode(uint256(keccak256("security.vault.storage.v1")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant VAULT_STORAGE_LOCATION =
        0x5a18a5fa2b2ff5438865c1926639d6756858a74e5ce6c98c0be9be93952f4100;

    struct VaultStorage {
        address owner;
        uint256 depositLimit;
        bool initialized;
    }

    // MITIGATION 1: Constructor locks initializers on the implementation bytecode itself
    constructor() {
        _getVaultStorage().initialized = true;
    }

    function _getVaultStorage() internal pure returns (VaultStorage storage $) {
        bytes32 slot = VAULT_STORAGE_LOCATION;
        assembly {
            $.slot := slot
        }
    }

    /// @notice Initialize function called via proxy
    function initializeProxy(address _owner, uint256 _limit) external {
        VaultStorage storage $ = _getVaultStorage();
        if ($.initialized) revert AlreadyInitialized();
        $.owner = _owner;
        $.depositLimit = _limit;
        $.initialized = true;
    }

    function getOwner() external view returns (address) {
        return _getVaultStorage().owner;
    }

    function getDepositLimit() external view returns (uint256) {
        return _getVaultStorage().depositLimit;
    }

    function isInitialized() external view returns (bool) {
        return _getVaultStorage().initialized;
    }
}
