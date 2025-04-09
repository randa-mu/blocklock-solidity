// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {TypesLib} from "../libraries/TypesLib.sol";
import {AbstractBlocklockReceiver} from "../AbstractBlocklockReceiver.sol";

contract MockBlocklockStringReceiver is AbstractBlocklockReceiver {
    uint256 public requestId;
    TypesLib.Ciphertext public encrytpedValue;
    string public plainTextValue;

    constructor(address blocklockContract) AbstractBlocklockReceiver(blocklockContract) {}

    function createTimelockRequest(
        uint32 callbackGasLimit,
        uint256 decryptionBlockNumber,
        TypesLib.Ciphertext calldata encryptedData
    ) external returns (uint256) {
        // create timelock request
        requestId = _requestBlocklock(callbackGasLimit, decryptionBlockNumber, encryptedData);
        // store Ciphertext
        encrytpedValue = encryptedData;
        return requestId;
    }

    function _onBlocklockReceived(uint256 requestID, bytes calldata decryptionKey) internal override {
        require(requestID == requestId, "Invalid request id");
        plainTextValue = abi.decode(decrypt(encrytpedValue, decryptionKey), (string));
    }
}
