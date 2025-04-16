// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {TypesLib} from "../libraries/TypesLib.sol";

import {ISubscription} from "../interfaces/ISubscription.sol";

/// @title IBlocklockSender interface
/// @author Randamu
/// @notice Interface for periphery smart contract used to interact with the decryption sender contract.
interface IBlocklockSender is ISubscription {
    /// @notice Requests the generation of a blocklock decryption key at a specific blockHeight.
    /// @dev Initiates a blocklock decryption key request.
    /// The blocklock decryption key will be generated once the chain reaches the specified `blockHeight`.
    /// @return requestID The unique identifier assigned to this blocklock request.
    function requestBlocklockWithSubscription(
        uint32 callbackGasLimit,
        uint256 subId,
        uint256 blockHeight,
        TypesLib.Ciphertext calldata ciphertext
    ) external payable returns (uint256 requestID);

    /// @notice Requests a blocklock for a specified block height with the provided ciphertext without a subscription ID.
    /// Requires payment to be made for the request without a subscription.
    /// @param callbackGasLimit The gas limit allocated for the callback execution after the blocklock request
    /// @param blockHeight The block height at which the blocklock is requested
    /// @param ciphertext The ciphertext that will be used in the blocklock request
    /// @return requestID The unique identifier for the blocklock request
    /// @dev This function allows users to request a blocklock for a specific block height. The blocklock is not associated with any subscription ID
    ///      and requires a ciphertext to be provided. The function checks that the contract is configured and not disabled before processing the request.
    function requestBlocklockWithoutSubscription(
        uint32 callbackGasLimit,
        uint256 blockHeight,
        TypesLib.Ciphertext calldata ciphertext
    ) external payable returns (uint256 requestID);

    /// @notice Calculates the estimated price in native tokens for a request based on the provided gas limit
    /// @param _callbackGasLimit The gas limit for the callback execution
    /// @return The estimated request price in native token (e.g., ETH)
    function calculateRequestPriceNative(uint32 _callbackGasLimit) external view returns (uint256);

    /// @notice Estimates the request price in native tokens using a specified gas price
    /// @param _callbackGasLimit The gas limit for the callback execution
    /// @param _requestGasPriceWei The gas price (in wei) to use for the estimation
    /// @return The estimated total request price in native token (e.g., ETH)
    function estimateRequestPriceNative(uint32 _callbackGasLimit, uint256 _requestGasPriceWei)
        external
        view
        returns (uint256);

    /// @notice Updates the decryptionn sender contract address
    /// @param newDecryptionSender The decryption sender address to set
    function setDecryptionSender(address newDecryptionSender) external;

    /// @notice Retrieves a specific request by its ID.
    /// @dev This function returns the Request struct associated with the given requestId.
    /// @param requestId The ID of the request to retrieve.
    /// @return The Request struct corresponding to the given requestId.
    function getRequest(uint256 requestId) external view returns (TypesLib.BlocklockRequest memory);

    /// Decrypt a ciphertext into a plaintext using a decryption key.
    /// @param ciphertext The ciphertext to decrypt.
    /// @param decryptionKey The decryption key that can be used to decrypt the ciphertext.
    function decrypt(TypesLib.Ciphertext calldata ciphertext, bytes calldata decryptionKey)
        external
        view
        returns (bytes memory);

    /// @dev Returns the version number of the upgradeable contract.
    function version() external pure returns (string memory);
}
