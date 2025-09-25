// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {SubscriptionAPI} from "../subscription/SubscriptionAPI.sol";
import {TypesLib} from "../libraries/TypesLib.sol";
import {BlocklockErrors} from "../libraries/BlocklockErrors.sol";

/// @title BlocklockSubscriptionLib library
/// @notice Library for handling subscription validation and payment logic
/// @dev This library extracts subscription-related functionality from BlocklockSender to reduce contract size
library BlocklockSubscriptionLib {
    /// @notice Custom error for invalid subscriptions
    error InvalidSubscription();

    /// @notice Validates callback gas limit for subscription requests
    /// @param _callbackGasLimit The gas limit for the callback function
    /// @param _subId The subscription ID (must be > 0)
    /// @param maxGasLimit The maximum allowed gas limit
    /// @param subscriptionConfigs Mapping of subscription configurations
    /// @param consumers Mapping of consumer configurations
    /// @dev Validates the subscription and updates consumer state
    function validateSubscriptionAndUpdateConsumer(
        uint32 _callbackGasLimit,
        uint256 _subId,
        uint32 maxGasLimit,
        mapping(uint256 => SubscriptionAPI.SubscriptionConfig) storage subscriptionConfigs,
        mapping(address => mapping(uint256 => SubscriptionAPI.ConsumerConfig)) storage consumers
    ) external {
        require(_callbackGasLimit <= maxGasLimit, "Callback gasLimit too high");

        address owner = subscriptionConfigs[_subId].owner;
        requireValidSubscription(owner);

        // Its important to ensure that the consumer is in fact who they say they
        // are, otherwise they could use someone else's subscription balance.
        mapping(uint256 => SubscriptionAPI.ConsumerConfig) storage consumerConfigs = consumers[msg.sender];

        SubscriptionAPI.ConsumerConfig memory consumerConfig = consumerConfigs[_subId];
        require(consumerConfig.active, "No active subscription for caller");

        ++consumerConfig.nonce;
        ++consumerConfig.pendingReqCount;
        consumerConfigs[_subId] = consumerConfig;
    }

    /// @notice Validates callback gas limit for direct funding requests
    /// @param _callbackGasLimit The gas limit for the callback function
    /// @param maxGasLimit The maximum allowed gas limit
    /// @param requestPrice The calculated price for this request
    /// @dev Validates payment amount for direct funding
    function validateDirectFundingRequest(uint32 _callbackGasLimit, uint32 maxGasLimit, uint256 requestPrice)
        external
        view
    {
        require(_callbackGasLimit <= maxGasLimit, "Callback gasLimit too high");
        require(msg.value >= requestPrice, "Fee too low");
    }

    /// @notice Updates subscription counters and charges payment for subscription requests
    /// @param request The blocklock request containing payment details
    /// @param payment The payment amount to charge
    /// @param subscriptions Mapping of subscription data
    /// @param consumers Mapping of consumer configurations
    /// @dev Updates request counts for subscription-based payments
    function handleSubscriptionPayment(
        TypesLib.BlocklockRequest memory request,
        uint96 payment,
        mapping(uint256 => SubscriptionAPI.Subscription) storage subscriptions,
        mapping(address => mapping(uint256 => SubscriptionAPI.ConsumerConfig)) storage consumers
    ) external returns (uint96) {
        ++subscriptions[request.subId].reqCount;
        --consumers[request.callback][request.subId].pendingReqCount;
        return payment;
    }

    /// @notice Returns the payment amount for direct funding requests
    /// @param request The blocklock request containing payment details
    /// @dev For direct funding, returns the amount already paid by the user
    function handleDirectFundingPayment(TypesLib.BlocklockRequest memory request) external pure returns (uint96) {
        return uint96(request.directFundingFeePaid);
    }

    /// @notice Validates that a subscription owner is valid (non-zero address)
    /// @param subOwner The subscription owner address to validate
    /// @dev Reverts if the owner address is zero (invalid subscription)
    function requireValidSubscription(address subOwner) public pure {
        if (subOwner == address(0)) {
            revert InvalidSubscription();
        }
    }
}
