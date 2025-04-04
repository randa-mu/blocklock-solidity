// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {IBlocklockReceiver} from "./interfaces/IBlocklockReceiver.sol";
import {IBlocklockSender, TypesLib} from "./interfaces/IBlocklockSender.sol";

abstract contract AbstractBlocklockReceiver is IBlocklockReceiver {
    IBlocklockSender public blocklock;

    modifier onlyBlocklockContract() {
        require(msg.sender == address(blocklock), "Only timelock contract can call this.");
        _;
    }

    constructor(address blocklockSender) {
        blocklock = IBlocklockSender(blocklockSender);
    }

    function requestBlocklock(uint256 blockHeight, TypesLib.Ciphertext calldata ciphertext)
        internal
        returns (uint256 requestID)
    {
        requestID = blocklock.requestBlocklock(blockHeight, ciphertext);
    }

    function receiveBlocklock(uint256 requestID, bytes calldata decryptionKey) external virtual onlyBlocklockContract {
        _onBlocklockReceived(requestID, decryptionKey);
    }

    function decrypt(TypesLib.Ciphertext memory ciphertext, bytes calldata decryptionKey)
        internal
        view
        returns (bytes memory)
    {
        return blocklock.decrypt(ciphertext, decryptionKey);
    }

    function _onBlocklockReceived(uint256 requestID, bytes calldata decryptionKey) internal virtual;
}
