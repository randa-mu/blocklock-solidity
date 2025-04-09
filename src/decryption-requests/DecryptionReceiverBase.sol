// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {TypesLib} from "../libraries/TypesLib.sol";
import {IDecryptionReceiver} from "../interfaces/IDecryptionReceiver.sol";
import {IDecryptionSender} from "../interfaces/IDecryptionSender.sol";

abstract contract DecryptionReceiverBase is IDecryptionReceiver {
    IDecryptionSender public decryptionSender;

    modifier onlyDecrypter() {
        require(msg.sender == address(decryptionSender), "Only DecryptionSender can call");
        _;
    }

    /**
     * @dev See {IDecryptionReceiver-registerCiphertext}.
     */
    function registerCiphertext(
        string calldata schemeID,
        uint32 callbackGasLimit,
        bytes memory ciphertext,
        bytes memory conditions
    ) internal returns (uint256 requestID) {
        return decryptionSender.registerCiphertext(schemeID, callbackGasLimit, ciphertext, conditions);
    }

    /**
     * @dev See {IDecryptionReceiver-receiveDecryptionData}.
     */
    function receiveDecryptionData(uint256 requestID, bytes calldata decryptionKey, bytes calldata signature)
        external
        onlyDecrypter
    {
        onDecryptionDataReceived(requestID, decryptionKey, signature);
    }

    /**
     * @dev Callback function that is triggered when a decryption key is received.
     * This function is intended to be overridden in derived contracts to implement
     * specific logic upon receiving a decryption key.
     *
     * @param requestID The unique identifier for the decryption key request.
     * This is useful for correlating the received key with the original request.
     *
     * @param decryptionKey The unique decryption key associated to a specific ciphertext.
     *
     * @param signature The signature used for the derivation of the decryptionKey.
     */
    function onDecryptionDataReceived(uint256 requestID, bytes memory decryptionKey, bytes memory signature)
        internal
        virtual;
}
