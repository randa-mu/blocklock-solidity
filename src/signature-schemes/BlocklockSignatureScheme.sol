// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {BLS} from "../libraries/BLS.sol";

import {SignatureSchemeBase} from "./SignatureSchemeBase.sol";

/// @title BlocklockSignatureScheme
/// @author Randamu
/// @dev This contract implements the BLS (Boneh-Lynn-Shacham) signature scheme using the 
/// BN254 curve for the Blocklock protocol.
/// The contract provides functionality to verify signatures, hash messages to points, 
/// and marshal/unmarshal points for signature verification.
contract BlocklockSignatureScheme is SignatureSchemeBase {
    using BLS for bytes;

    string public constant SCHEME_ID = "BN254-BLS-BLOCKLOCK";
    bytes public constant DST = bytes("BLOCKLOCK_BN254G1_XMD:KECCAK-256_SVDW_RO_H1_");

    constructor(uint256[2] memory x, uint256[2] memory y) SignatureSchemeBase(x, y) {}

    /// @dev See {ISignatureScheme-verifySignature}.
    /// @param message The message whose signature is being verified.
    /// @param signature The BLS signature to be verified.
    /// @param publicKey The public key associated with the signature.
    /// @return isValid A boolean value indicating if the signature is valid.
    function verifySignature(bytes calldata message, bytes calldata signature, bytes calldata publicKey)
        external
        view
        returns (bool isValid)
    {
        // convert message hash bytes to g1
        BLS.PointG1 memory _message = BLS.g1Unmarshal(message);
        // convert signature bytes to g1
        BLS.PointG1 memory _signature = BLS.g1Unmarshal(signature);
        // convert public key bytes to g2
        BLS.PointG2 memory _publicKey = BLS.g2Unmarshal(publicKey);
        // call evm precompile for pairing check
        (bool pairingSuccess, bool callSuccess) = BLS.verifySingle(_signature, _publicKey, _message);
        return (pairingSuccess && callSuccess);
    }

    /// @dev See {ISignatureScheme-hashToPoint}.
    /// @param message The message to be hashed to a point on the elliptic curve.
    /// @return x The x-coordinate of the point.
    /// @return y The y-coordinate of the point.
    function hashToPoint(bytes calldata message) public view returns (uint256, uint256) {
        BLS.PointG1 memory point = BLS.hashToPoint(DST, message);
        return (point.x, point.y);
    }

    /// @dev See {ISignatureScheme-hashToBytes}.
    /// @param message The message to be hashed to bytes.
    /// @return The marshaled bytes representing the point corresponding to the message.
    function hashToBytes(bytes calldata message) external view returns (bytes memory) {
        (uint256 x, uint256 y) = hashToPoint(message);
        return BLS.g1Marshal(BLS.PointG1({x: x, y: y}));
    }
}
