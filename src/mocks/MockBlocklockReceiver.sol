// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {TypesLib} from "../libraries/TypesLib.sol";
import {AbstractBlocklockReceiver} from "../AbstractBlocklockReceiver.sol";

/// @notice This contract is used for testing only and should not be used for production.
contract MockBlocklockReceiver is AbstractBlocklockReceiver {
    uint256 public requestId;
    TypesLib.Ciphertext public encrytpedValue;
    uint256 public plainTextValue;

    constructor(address blocklockContract) AbstractBlocklockReceiver(blocklockContract) {}

    function createTimelockRequestWithDirectFunding(
        uint32 callbackGasLimit,
        uint256 blockHeight,
        TypesLib.Ciphertext calldata encryptedData
    ) external returns (uint256, uint256) {
        // create timelock request
        (uint256 requestID, uint256 requestPrice) =
            _requestBlocklockPayInNative(callbackGasLimit, blockHeight, encryptedData);
        // store request id
        requestId = requestID;
        // store Ciphertext
        encrytpedValue = encryptedData;
        return (requestID, requestPrice);
    }

    function createTimelockRequestWithSubscription(
        uint32 callbackGasLimit,
        uint256 blockHeight,
        TypesLib.Ciphertext calldata encryptedData
    ) external payable returns (uint256) {
        // create timelock request
        uint256 requestID = _requestBlocklockWithSubscription(callbackGasLimit, blockHeight, encryptedData);
        // store Ciphertext
        encrytpedValue = encryptedData;
        return requestID;
    }

    function _onBlocklockReceived(uint256 requestID, bytes calldata decryptionKey) internal override {
        require(requestID == requestId, "Invalid request id.");
        // decrypt stored Ciphertext with decryption key
        plainTextValue = abi.decode(blocklock.decrypt(encrytpedValue, decryptionKey), (uint256));
    }
}
