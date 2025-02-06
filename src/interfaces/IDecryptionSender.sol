// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {TypesLib} from "../libraries/TypesLib.sol";

/// @notice Smart contract that stores and conditionally decrypts encrypted messages / data
interface IDecryptionSender {
    /// Setters

    /// @notice Registers a Ciphertext and associated conditions for decryption
    /// @notice creation of the `Ciphertext` and `conditions` bytes will be managed by a javascript client library off-chain
    /// @dev The creation of `Ciphertext` and `conditions` bytes will be managed by the JavaScript client library
    /// @param ciphertext The encrypted data to be registered
    /// @param conditions The conditions that need to be met to decrypt the ciphertext
    /// @return requestID The unique ID assigned to the registered decryption request
    function registerCiphertext(string calldata schemeID, bytes calldata ciphertext, bytes calldata conditions)
        external
        returns (uint256 requestID);

    /**
     * @notice Provide the decryption key for a specific requestID alongside a signature.
     * @dev This function is intended to be called after a decryption key has been generated off-chain.
     *
     * @param requestID The unique identifier for the encryption request. This should match the ID used
     *                  when the encryption was initially requested.
     * @param decryptionKey The decrypted content in bytes format. The data should represent the original
     *                      message in its decrypted form.
     * @param signature The signature associated with the request, provided as a byte array
     */
    function fulfilDecryptionRequest(uint256 requestID, bytes calldata decryptionKey, bytes calldata signature)
        external;

    /**
     * @notice Retry an request that has previously failed during callback
     * @dev This function is intended to be called after a decryption key has been generated off-chain but failed to
     * call back into the originating contract.
     *
     * @param requestID The unique identifier for the encryption request. This should match the ID used
     *                  when the encryption was initially requested.
     */
    function retryCallback(uint256 requestID) external;

    /**
     * @notice Updates the signature scheme address provider contract address
     * @param newSignatureSchemeAddressProvider The signature address provider address to set
     */
    function setSignatureSchemeAddressProvider(address newSignatureSchemeAddressProvider) external;

    // Getters

    /**
     * @notice Retrieves a specific request by its ID.
     * @dev This function returns the Request struct associated with the given requestId.
     * @param requestId The ID of the request to retrieve.
     * @return The Request struct corresponding to the given requestId.
     */
    function getRequest(uint256 requestId) external view returns (TypesLib.DecryptionRequest memory);

    /**
     * @notice Verifies whether a specific request is in flight or not.
     * @param requestID The ID of the request to check.
     * @return boolean indicating whether the request is in flight or not.
     */
    function isInFlight(uint256 requestID) external view returns (bool);

    /**
     * @notice returns whether a specific request errored during callback or not.
     * @param requestID The ID of the request to check.
     * @return boolean indicating whether the request has errored or not.
     */
    function hasErrored(uint256 requestID) external view returns (bool);

    /**
     * @notice Retrieves the public key associated with the decryption process.
     * @dev Returns the public key as two elliptic curve points.
     * @return Two pairs of coordinates representing the public key points on the elliptic curve.
     */
    function getPublicKey() external view returns (uint256[2] memory, uint256[2] memory);

    /**
     * @notice Retrieves the public key associated with the decryption process.
     * @dev Returns the public key as bytes.
     * @return Bytes string representing the public key points on the elliptic curve.
     */
    function getPublicKeyBytes() external view returns (bytes memory);

    /**
     * @notice Returns all the fulfilled request ids.
     * @return A uint array representing a set containing all fulfilled request ids.
     */
    function getAllFulfilledRequestIds() external view returns (uint256[] memory);

    /**
     * @notice Returns all the request ids that are yet to be fulfilled.
     * @return A uint array representing a set containing all request ids that are yet to be fulfilled.
     */
    function getAllUnfulfilledRequestIds() external view returns (uint256[] memory);

    /**
     * @notice Returns count of all the request ids that are yet to be fulfilled.
     * @return A uint representing a count of all request ids that are yet to be fulfilled.
     */
    function getCountOfUnfulfilledRequestIds() external view returns (uint256);

    /**
     * @dev Returns the version number of the upgradeable contract.
     */
    function version() external pure returns (string memory);
}
