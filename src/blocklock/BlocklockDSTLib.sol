// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {BytesLib} from "../libraries/BytesLib.sol";

/// @title BlocklockDSTLib library
/// @notice Library for Domain Separation Tag (DST) initialization
/// @dev Extracts DST creation logic to reduce contract size
library BlocklockDSTLib {
    using BytesLib for bytes32;

    /// @notice Initializes all Domain Separation Tags for the blocklock scheme
    /// @param chainId The chain ID to include in DST generation
    /// @return dst_h1_g1 The DST for H1 operations
    /// @return dst_h2 The DST for H2 operations
    /// @return dst_h3 The DST for H3 operations
    /// @return dst_h4 The DST for H4 operations
    function initializeDSTs(uint256 chainId)
        external
        pure
        returns (bytes memory dst_h1_g1, bytes memory dst_h2, bytes memory dst_h3, bytes memory dst_h4)
    {
        string memory chainIdHexStr = bytes32(chainId).toHexString();
        bytes memory chainIdHex = bytes(chainIdHexStr);

        dst_h1_g1 = abi.encodePacked("BLOCKLOCK_BN254G1_XMD:KECCAK-256_SVDW_RO_H1_", chainIdHex, "_");
        dst_h2 = abi.encodePacked("BLOCKLOCK_BN254_XMD:KECCAK-256_H2_", chainIdHex, "_");
        dst_h3 = abi.encodePacked("BLOCKLOCK_BN254_XMD:KECCAK-256_H3_", chainIdHex, "_");
        dst_h4 = abi.encodePacked("BLOCKLOCK_BN254_XMD:KECCAK-256_H4_", chainIdHex, "_");
    }
}
