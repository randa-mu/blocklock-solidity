// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {TypesLib} from "../libraries/TypesLib.sol";
import {IDecryptionReceiver} from "../interfaces/IDecryptionReceiver.sol";
import {IDecryptionSender} from "../interfaces/IDecryptionSender.sol";

/// @title DecryptionReceiverBase contract
/// @author Randamu
/// @notice Abstract contract for registering Ciphertexts and
/// handling the reception of decryption data from the DecryptionSender contract
abstract contract DecryptionReceiverBase is IDecryptionReceiver {
    /// @notice The DecryptionSender contract authorized to send decryption data
    IDecryptionSender public decryptionSender;

    /// @notice Modifier to restrict access to only the DecryptionSender contract
    modifier onlyDecrypter() {
        require(msg.sender == address(decryptionSender), "Only DecryptionSender can call");
        _;
    }

    /// @dev Forwards a ciphertext registration request to the DecryptionSender contract
    ///      which sets up a conditional encryption request.
    /// @param schemeID Identifier of the encryption scheme used.
    /// @param ciphertext The encrypted data to be decrypted.
    /// @param condition The condition for decryption.
    /// @return requestId A unique identifier for the submitted decryption request.
    function _registerCiphertext(string memory schemeID, bytes memory ciphertext, bytes memory condition)
        internal
        returns (uint256 requestId)
    {
        return decryptionSender.registerCiphertext(schemeID, ciphertext, condition);
    }

    /// @dev Called by the DecryptionSender to deliver the decryption key and its signature
    /// @param requestId The identifier of the original decryption request
    /// @param decryptionKey The derived decryption key
    /// @param signature Signature used in the key derivation process
    function receiveDecryptionData(uint256 requestId, bytes calldata decryptionKey, bytes calldata signature)
        external
        onlyDecrypter
    {
        onDecryptionDataReceived(requestId, decryptionKey, signature);
    }

    /// @notice Callback function triggered when a decryption key is received
    /// @dev Must be implemented in derived contracts to define how to handle the received decryption data
    /// @param requestId The unique identifier of the decryption request
    /// @param decryptionKey The decryption key associated with the ciphertext
    /// @param signature The signature used to derive the decryption key
    function onDecryptionDataReceived(uint256 requestId, bytes memory decryptionKey, bytes memory signature)
        internal
        virtual;
}
