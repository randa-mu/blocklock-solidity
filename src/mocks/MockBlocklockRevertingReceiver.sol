// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {TypesLib} from "../libraries/TypesLib.sol";
import {AbstractBlocklockReceiver} from "../AbstractBlocklockReceiver.sol";

/// @notice This contract is used for testing only and should not be used for production.
contract MockBlocklockRevertingReceiver is AbstractBlocklockReceiver {
    uint256 public requestId;
    TypesLib.Ciphertext public encryptedValue;
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
        encryptedValue = encryptedData;
        return (requestID, requestPrice);
    }

    function createTimelockRequestWithSubscription(
        uint32 callbackGasLimit,
        uint256 blockHeight,
        TypesLib.Ciphertext calldata encryptedData
    ) external payable returns (uint256) {
        // create timelock request
        uint256 requestID = _requestBlocklockWithSubscription(callbackGasLimit, blockHeight, encryptedData);
        // store request id
        requestId = requestID;
        // store Ciphertext
        encryptedValue = encryptedData;
        return requestID;
    }

    function _onBlocklockReceived(uint256, /*_requestId*/ bytes calldata /*decryptionKey*/ ) internal pure override {
        revert();
    }
}
