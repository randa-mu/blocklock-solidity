// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {TypesLib} from "../libraries/TypesLib.sol";
import {AbstractBlocklockReceiver} from "../AbstractBlocklockReceiver.sol";

contract MockBlocklockRevertingReceiver is AbstractBlocklockReceiver {
    uint256 public requestId;
    TypesLib.Ciphertext public encrytpedValue;
    uint256 public plainTextValue;

    constructor(address blocklockContract) AbstractBlocklockReceiver(blocklockContract) {}

    function createTimelockRequestWithDirectFunding(
        uint32 callbackGasLimit,
        uint256 blockHeight,
        TypesLib.Ciphertext calldata encryptedData
    ) external payable returns (uint256, uint256) {
        // create timelock request
        (uint256 requestID, uint256 requestPrice) =
            _requestBlocklockPayInNative(callbackGasLimit, blockHeight, encryptedData);
        // store Ciphertext
        encrytpedValue = encryptedData;
        return (requestID, requestPrice);
    }

    function _onBlocklockReceived(uint256, /*requestID*/ bytes calldata /*decryptionKey*/ ) internal pure override {
        revert();
    }
}
