// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

/// @title Factory Contract
/// @notice Allows deterministic deployment of contracts using CREATE2
/// @dev Useful for deploying contracts to predictable addresses
contract Factory {
    /// @notice Reverts when the provided bytecode is empty
    error Create2EmptyBytecode();

    /// @notice Reverts when deployment via CREATE2 fails
    error Create2FailedDeployment();

    /// @notice Emitted when a contract is successfully deployed using CREATE2
    /// @param addr The address of the deployed contract
    /// @param salt The salt used in the CREATE2 deployment
    event CreatedContract(address addr, bytes32 salt);

    /// @notice Deploys a contract using the CREATE2 opcode
    /// @dev Uses `callvalue()` to support deployments with ETH
    /// @param salt A user-provided salt to make the deployment address deterministic
    /// @param creationCode The bytecode of the contract to deploy
    /// @return addr The address of the deployed contract
    function deploy(bytes32 salt, bytes memory creationCode) external payable returns (address addr) {
        if (creationCode.length == 0) {
            revert Create2EmptyBytecode();
        }

        assembly {
            addr := create2(callvalue(), add(creationCode, 0x20), mload(creationCode), salt)
        }

        if (addr == address(0)) {
            revert Create2FailedDeployment();
        }

        emit CreatedContract(addr, salt);

        return addr;
    }

    /// @notice Computes the address where a contract will be deployed using CREATE2
    /// @dev This follows the CREATE2 formula: keccak256(0xff ++ sender ++ salt ++ keccak256(bytecode))[12:]
    /// @param salt The salt to be used for deployment
    /// @param creationCodeHash The keccak256 hash of the contract creation bytecode
    /// @return addr The deterministic address of the contract if deployed with the same salt and bytecode
    function computeAddress(bytes32 salt, bytes32 creationCodeHash) external view returns (address addr) {
        address contractAddress = address(this);

        assembly {
            let ptr := mload(0x40)

            mstore(add(ptr, 0x40), creationCodeHash)
            mstore(add(ptr, 0x20), salt)
            mstore(ptr, contractAddress)
            let start := add(ptr, 0x0b)
            mstore8(start, 0xff)
            addr := keccak256(start, 85)
        }
    }
}
