// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Minimal ERC-1967 Proxy pattern addressing the EVM Immutability limitation.
contract MinimalProxy {
    // bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
    bytes32 private constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    // bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1)
    bytes32 private constant ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    event Upgraded(address indexed implementation);

    constructor(address logic, address admin) {
        _setAdmin(admin);
        _setImplementation(logic);
    }

    modifier onlyAdmin() {
        require(msg.sender == _getAdmin(), "Caller is not proxy admin");
        _;
    }

    function upgradeTo(address newImplementation) external onlyAdmin {
        require(newImplementation != address(0), "Invalid implementation");
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    function _setImplementation(address newImplementation) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }

    function _setAdmin(address newAdmin) internal {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            sstore(slot, newAdmin)
        }
    }

    function _getImplementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    function _getAdmin() internal view returns (address adm) {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            adm := sload(slot)
        }
    }

    fallback() external payable {
        address impl = _getImplementation();
        require(impl != address(0), "Implementation not set");
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    receive() external payable {}
}

/// @notice Logic Contract Version 1
contract LogicV1 {
    uint256 public value;
    bool internal _initialized;

    function initialize(uint256 _initialValue) external {
        require(!_initialized, "Already initialized");
        value = _initialValue;
        _initialized = true;
    }

    function setValue(uint256 _value) external {
        value = _value;
    }

    function getVersion() external pure returns (string memory) {
        return "V1";
    }
}

/// @notice Logic Contract Version 2 with extended logic and storage safety
contract LogicV2 {
    uint256 public value;
    bool internal _initialized;
    // New variable appended safely to end of storage layout (no collision)
    uint256 public multiplier;

    function setMultiplier(uint256 _multiplier) external {
        multiplier = _multiplier;
    }

    function getMultipliedValue() external view returns (uint256) {
        return value * multiplier;
    }

    function getVersion() external pure returns (string memory) {
        return "V2";
    }
}
