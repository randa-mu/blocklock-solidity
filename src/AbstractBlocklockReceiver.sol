// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {IBlocklockReceiver} from "./interfaces/IBlocklockReceiver.sol";
import {IBlocklockSender, TypesLib} from "./interfaces/IBlocklockSender.sol";

import {ConfirmedOwner} from "./access/ConfirmedOwner.sol";

abstract contract AbstractBlocklockReceiver is IBlocklockReceiver, ConfirmedOwner {
    IBlocklockSender public blocklock;

    /// @notice The Randamu subscription ID used for conditional encryption.
    /// @dev Used in interactions with IBlocklockSender for subscription management, e.g., 
    /// @dev funding and consumer contract address registration.
    uint256 public subscriptionId;

    modifier onlyBlocklockContract() {
        require(msg.sender == address(blocklock), "Only timelock contract can call this.");
        _;
    }

    constructor(address blocklockSender) ConfirmedOwner(msg.sender) {
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

    /// @notice Sets the Randamu subscription ID used for conitional encryption oracle services.
    /// @dev Only callable by the contract owner.
    /// @param subId The new subscription ID to be set.
    function setSubId(uint256 subId) external onlyOwner {
        subscriptionId = subId;
    }

    /// @notice getBalance returns the native balance of the consumer contract
    /// @notice For direct funding requests, the contract needs to hold native tokens to
    /// sufficient enough to cover the cost of the request.
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
