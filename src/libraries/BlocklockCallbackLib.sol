// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {TypesLib} from "./TypesLib.sol";
import {IBlocklockReceiver} from "../interfaces/IBlocklockReceiver.sol";
import {CallWithExactGas} from "./CallWithExactGas.sol";
import {BlocklockSubscriptionLib} from "../blocklock/BlocklockSubscriptionLib.sol";
import {BlocklockErrors} from "./BlocklockErrors.sol";

/// @title BlocklockCallbackLib
/// @notice External library for handling blocklock callbacks
library BlocklockCallbackLib {
    using CallWithExactGas for bytes;

    /// @notice Handles blocklock callback execution
    function executeCallback(
        TypesLib.BlocklockRequest storage request,
        uint256 decryptionRequestId,
        bytes memory decryptionKey,
        bytes memory signature,
        uint32 gasForCallExactCheck
    ) external returns (bool success) {
        bytes memory callbackCallData =
            abi.encodeWithSelector(IBlocklockReceiver.receiveBlocklock.selector, decryptionRequestId, decryptionKey);

        (success,) = callbackCallData._callWithExactGasEvenIfTargetIsNoContract(
            request.callback, request.callbackGasLimit, gasForCallExactCheck
        );

        if (success) {
            request.decryptionKey = decryptionKey;
            request.signature = signature;
        }
    }
}