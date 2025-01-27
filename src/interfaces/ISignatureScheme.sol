// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface ISignatureScheme {
    /// Getters

    /**
     * @notice Returns the scheme identifier as a string, e.g., "BN254", "BLS12-381", "TESS"
     */
    function SCHEME_ID() external returns (string memory);

    /**
     * @notice Verifies a signature using the given signature scheme.
     * @param message The message that was signed. Message is a G1 point represented as bytes.
     * @param signature The signature to verify. Signature is a G1 point represented as bytes.
     * @param publicKey The public key of the signer. Public key is a G2 point represented as bytes.
     * @return isValid boolean which evaluates to true if the signature is valid, false otherwise.
     */
    function verifySignature(bytes calldata message, bytes calldata signature, bytes calldata publicKey)
        external
        view
        returns (bool isValid);

    /**
     * @notice Hashes a message to a G1 point on the elliptic curve.
     * @param message The message to be hashed.
     * @return (uint256, uint256) A point on the elliptic curve in G1, represented as x and y coordinates.
     */
    function hashToPoint(bytes memory message) external view returns (uint256, uint256);
    /**
     * @notice Hashes a message to a G1 point on the elliptic curve.
     * @param message The message to be hashed.
     * @return bytes A point on the elliptic curve in G1, represented as bytes.
     */
    function hashToBytes(bytes calldata message) external view returns (bytes memory);
}
