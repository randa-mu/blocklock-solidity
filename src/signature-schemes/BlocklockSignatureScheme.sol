// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {BLS} from "../libraries/BLS.sol";

import {SignatureSchemeBase} from "./SignatureSchemeBase.sol";

/// @title BlocklockSignatureScheme contract
/// @author Randamu
/// @dev This contract implements the BLS (Boneh-Lynn-Shacham) signature scheme using the
/// BN254 curve for the Blocklock protocol.
/// @dev The contract provides functionality to verify signatures, hash messages to points,
/// and marshal/unmarshal points for signature verification.
contract BlocklockSignatureScheme is SignatureSchemeBase {
    using BLS for bytes;

    string public constant SCHEME_ID = "BN254-BLS-BLOCKLOCK";
    bytes public constant DST = bytes("BLOCKLOCK_BN254G1_XMD:KECCAK-256_SVDW_RO_H1_");

    constructor(uint256[2] memory x, uint256[2] memory y) SignatureSchemeBase(x, y) {}

    /// @notice Verifies a signature using the given signature scheme.
    /// @param message The message that was signed. Message is a G1 point represented as bytes.
    /// @param signature The signature to verify. Signature is a G1 point represented as bytes.
    /// @param publicKey The public key of the signer. Public key is a G2 point represented as bytes.
    /// @return isValid boolean which evaluates to true if the signature is valid, false otherwise.
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

    /// @notice Hashes a message to a G1 point on the elliptic curve.
    /// @param message The message to be hashed.
    /// @return (uint256, uint256) A point on the elliptic curve in G1, represented as x and y coordinates.
    function hashToPoint(bytes calldata message) public view returns (uint256, uint256) {
        BLS.PointG1 memory point = BLS.hashToPoint(DST, message);
        return (point.x, point.y);
    }

    /// @notice Hashes a message to a G1 point on the elliptic curve.
    /// @param message The message to be hashed.
    /// @return bytes The marshaled bytes representing the point corresponding to the message.
    function hashToBytes(bytes calldata message) external view returns (bytes memory) {
        (uint256 x, uint256 y) = hashToPoint(message);
        return BLS.g1Marshal(BLS.PointG1({x: x, y: y}));
    }
}
