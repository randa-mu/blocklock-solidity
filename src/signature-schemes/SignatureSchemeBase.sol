// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {BLS} from "../libraries/BLS.sol";

import {ISignatureScheme} from "../interfaces/ISignatureScheme.sol";

/// @title SignatureSchemeBase contract
/// @author Randamu
/// @notice Base contract that all signature scheme contracts must implement.
abstract contract SignatureSchemeBase is ISignatureScheme {
    /// @notice Links public keys of threshold network statically to signature scheme contracts and remove from constructor of sender contracts. Admin cannot update, simply use new scheme id.
    BLS.PointG2 private publicKey = BLS.PointG2({x: [uint256(0), uint256(0)], y: [uint256(0), uint256(0)]});

    constructor(uint256[2] memory x, uint256[2] memory y) {
        publicKey = BLS.PointG2({x: x, y: y});
    }

    /// @notice Retrieves the public key associated with the decryption process.
    /// @dev Returns the public key as two elliptic curve points.
    /// @return Two pairs of coordinates representing the public key points on the elliptic curve.
    function getPublicKey() public view returns (uint256[2] memory, uint256[2] memory) {
        return (publicKey.x, publicKey.y);
    }

    /// @notice Retrieves the public key associated with the decryption process.
    /// @dev Returns the public key as bytes.
    /// @return Bytes string representing the public key points on the elliptic curve.
    function getPublicKeyBytes() public view returns (bytes memory) {
        return BLS.g2Marshal(publicKey);
    }

    /// @notice Returns the current blockchain chain ID.
    /// @dev Uses inline assembly to retrieve the `chainid` opcode.
    /// @return chainId The current chain ID of the network.
    function getChainId() public view returns (uint256 chainId) {
        assembly {
            chainId := chainid()
        }
    }
}
