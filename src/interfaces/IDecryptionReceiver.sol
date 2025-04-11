// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

/// @title IDecryptionReceiver interface
/// @author Randamu
/// @notice Interface for smart contract that recieives decryption key and associated
/// signature for user conditional decryption requests.
interface IDecryptionReceiver {
    /// @notice Receives a decryption key that can be used to decrypt the ciphertext
    /// @dev This function is intended to be called by an authorized decrypter contract
    /// @param requestID The ID of the request for which the decryption key is provided
    /// @param decryptionKey The decryption key associated with the request, provided as a byte array
    /// @param signature The signature associated with the request, provided as a byte array
    function receiveDecryptionData(uint256 requestID, bytes calldata decryptionKey, bytes calldata signature)
        external;
}
