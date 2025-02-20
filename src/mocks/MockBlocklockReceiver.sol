// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {TypesLib} from "../libraries/TypesLib.sol";
import {AbstractBlocklockReceiver} from "../AbstractBlocklockReceiver.sol";

contract MockBlocklockReceiver is AbstractBlocklockReceiver {
    uint256 public requestId;
    TypesLib.Ciphertext public encrytpedValue;
    uint256 public plainTextValue;

    constructor(address blocklockContract) AbstractBlocklockReceiver(blocklockContract) {}

    function createTimelockRequest(uint256 decryptionBlockNumber, TypesLib.Ciphertext calldata encryptedData)
        external
        returns (uint256)
    {
        // create timelock request
        requestId = blocklock.requestBlocklock(decryptionBlockNumber, encryptedData);
        // store Ciphertext
        encrytpedValue = encryptedData;
        return requestId;
    }

    function receiveBlocklock(uint256 requestID, bytes calldata decryptionKey)
        external
        override
        onlyBlocklockContract
    {
        require(requestID == requestId, "Invalid request id.");
        // decrypt stored Ciphertext with decryption key
        plainTextValue = abi.decode(blocklock.decrypt(encrytpedValue, decryptionKey), (uint256));
    }
}
