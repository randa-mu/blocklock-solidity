// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../libraries/TypesLib.sol";

interface ISignatureSender {
    /// Setters

    /**
     * @notice Requests a digital signature for a given message using a specified signature scheme.
     * @dev Initiates a request for signing the provided `message` under the specified `schemeID`.
     * The request may include certain conditions that need to be met.
     * @param schemeID The identifier of the signature scheme to be used.
     * @param message The message to be signed, provided as a byte array.
     * @param condition Conditions that must be satisfied for the signature request, provided as a byte array.
     * @return The unique request ID assigned to this signature request.
     */
    function requestSignature(string calldata schemeID, bytes calldata message, bytes calldata condition)
        external
        returns (uint256);

    /**
     * @notice Fulfills a signature request by providing the corresponding signature.
     * @dev Completes the signing process for the request identified by `requestID`.
     * The signature should be valid for the originally requested message.
     * @param requestID The unique identifier of the signature request being fulfilled.
     * @param signature The generated signature, provided as a byte array.
     */
    function fulfilSignatureRequest(uint256 requestID, bytes calldata signature) external;

    /// Getters

    /**
     * @notice Checks if a signature request is still in flight.
     * @dev Determines whether the specified `requestID` is still pending.
     * @param requestID The unique identifier of the signature request.
     * @return True if the request is still in flight, otherwise false.
     */
    function isInFlight(uint256 requestID) external view returns (bool);

    /**
     * @notice Returns request data if a signature request is still in flight.
     * @param requestID The unique identifier of the signature request.
     * @return The corresponding SignatureRequest struct if the request is still in flight, otherwise struct with zero values.
     */
    function getRequestInFlight(uint256 requestID) external view returns (TypesLib.SignatureRequest memory);

    /**
     * @notice Retrieves the public key associated with the signature process.
     * @dev Returns the public key as two elliptic curve points.
     * @return Two pairs of coordinates representing the public key points on the elliptic curve.
     */
    function getPublicKey() external view returns (uint256[2] memory, uint256[2] memory);
    /**
     * @notice Retrieves the public key associated with the signature process.
     * @dev Returns the public key as bytes.
     * @return Bytes string representing the public key points on the elliptic curve.
     */
    function getPublicKeyBytes() external view returns (bytes memory);
}
