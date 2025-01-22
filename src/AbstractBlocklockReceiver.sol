// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IBlocklockReceiver} from "./interfaces/IBlocklockReceiver.sol";
import {IBlocklockSender} from "./interfaces/IBlocklockSender.sol";

abstract contract AbstractBlocklockReceiver is IBlocklockReceiver {
    IBlocklockSender public blocklock;

    modifier onlyBlocklockContract() {
        require(msg.sender == address(blocklock), "Only timelock contract can call this.");
        _;
    }

    constructor(address blocklockSender) {
        blocklock = IBlocklockSender(blocklockSender);
    }

    function receiveBlocklock(uint256 requestID, bytes calldata decryptionKey) external virtual onlyBlocklockContract {}
}
