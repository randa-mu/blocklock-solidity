// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {TypesLib} from "../libraries/TypesLib.sol";

import {ISubscription} from "./ISubscription.sol";

/// @title IBlocklockSender interface
/// @author Randamu
/// @notice Interface for periphery smart contract used to interact with the decryption sender contract.
interface IBlocklockSender is ISubscription {
    /// @notice Requests a blocklock for a specified condition with the provided ciphertext without a subscription ID.
    /// Requires payment to be made for the request without a subscription.
    /// @param callbackGasLimit How much gas you'd like to receive in your
    /// receiveBlocklock callback. Note that gasleft() inside receiveBlocklock
    /// may be slightly less than this amount because of gas used calling the function
    /// (argument decoding etc.), so you may need to request slightly more than you expect
    /// to have inside receiveBlocklock. The acceptable range is
    /// [0, maxGasLimit]
    /// @param condition The condition for decryption represented as bytes.
    /// The decryption key is sent to the requesting callback / contract address
    /// when the condition is met.
    /// @param ciphertext The ciphertext that will be used in the blocklock request
    /// @dev This function allows users to request a blocklock for a specific condition.
    ///      The blocklock is not associated with any subscription ID
    ///      and requires a ciphertext to be provided. The function checks that the contract is
    ///      configured and not disabled before processing the request.
    function requestBlocklock(
        uint32 callbackGasLimit,
        bytes calldata condition,
        TypesLib.Ciphertext calldata ciphertext
    ) external payable returns (uint256 requestID);

    /// @notice Requests a blocklock for a specified condition with the provided ciphertext and subscription ID
    /// @param callbackGasLimit How much gas you'd like to receive in your
    /// receiveBlocklock callback. Note that gasleft() inside receiveBlocklock
    /// may be slightly less than this amount because of gas used calling the function
    /// (argument decoding etc.), so you may need to request slightly more than you expect
    /// to have inside receiveBlocklock. The acceptable range is
    /// [0, maxGasLimit]
    /// @param subId The subscription ID associated with the request
    /// @param condition The condition for decryption represented as bytes.
    /// The decryption key is sent to the requesting callback / contract address
    /// when the condition is met.
    /// @param ciphertext The ciphertext that will be used in the blocklock request
    /// @return requestID The unique identifier for the blocklock request
    /// @dev This function allows users to request a blocklock for a specific condition.
    ///      The blocklock is associated with a given subscription ID
    ///      and requires a ciphertext to be provided. The function checks that the contract is
    ///      configured and not disabled before processing the request.
    function requestBlocklockWithSubscription(
        uint32 callbackGasLimit,
        uint256 subId,
        bytes calldata condition,
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

    /// @notice Returns the current blockchain chain ID.
    /// @dev Uses inline assembly to retrieve the `chainid` opcode.
    /// @return chainId The current chain ID of the network.
    function getChainId() external view returns (uint256 chainId);
}
