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
        bytes calldata condition,
        TypesLib.Ciphertext calldata encryptedData
    ) external payable returns (uint256, uint256) {
        // create timelock request
        (uint256 _requestId, uint256 requestPrice) =
            _requestBlocklockPayInNative(callbackGasLimit, condition, encryptedData);
        // store request id
        requestId = _requestId;
        // store Ciphertext
        encryptedValue = encryptedData;
        return (requestId, requestPrice);
    }

    function createTimelockRequestWithSubscription(
        uint32 callbackGasLimit,
        bytes calldata condition,
        TypesLib.Ciphertext calldata encryptedData
    ) external returns (uint256) {
        // create timelock request
        uint256 _requestId = _requestBlocklockWithSubscription(callbackGasLimit, condition, encryptedData);
        // store request id
        requestId = _requestId;
        // store Ciphertext
        encryptedValue = encryptedData;
        return requestId;
    }

    function _onBlocklockReceived(uint256, /*_requestId*/ bytes calldata /*decryptionKey*/ ) internal pure override {
        revert();
    }
}
