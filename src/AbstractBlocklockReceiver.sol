// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IBlocklockReceiver} from "./interfaces/IBlocklockReceiver.sol";
import {IBlocklockSender} from "./interfaces/IBlocklockSender.sol";

abstract contract AbstractBlocklockReceiver is IBlocklockReceiver {
    IBlocklockSender public blocklockProvider;

    modifier onlyBlocklockContract() {
        require(msg.sender == address(blocklockProvider), "Only timelock contract can call this.");
        _;
    }

    constructor(address blocklockSender) {
        blocklockProvider = IBlocklockSender(blocklockSender);
    }

    function requestBlocklock(uint256 blockHeight, TypesLib.Ciphertext calldata ciphertext) internal returns (uint256 requestID) {
        requestID = blocklockProvider.requestBlocklock(uint256 blockHeight, TypesLib.Ciphertext calldata ciphertext);
    }

    function receiveBlocklock(uint256 requestID, bytes calldata decryptionKey) external virtual onlyBlocklockContract {
        onBlocklockReceived(requestID, decryptionKey);
    }

    /**
     * @notice Handles the reception of a generated random value for a specific request.
     * @dev This internal function is called when randomness is received for the given `requestID`.
     * It is intended to be overridden by derived contracts to implement custom behavior.
     * @param requestID The unique identifier of the randomness request.
     * @param decryptionKey The key required for the decryption associated with this requestID, provided as a `bytes32` type.
     */
    function onBlocklockReceived(uint256 requestID, bytes calldata decryptionKey) internal virtual;
}
