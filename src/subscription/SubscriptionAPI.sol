// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {ISubscription} from "../interfaces/ISubscription.sol";

/// @title Subscription API contract
/// @notice Abstract contract for managing user subscription accounts for onchain services.
/// @notice Minimal version of Chainlinks SubscriptionAPI contract.
/// @notice Available at https://github.com/smartcontractkit/chainlink/blob/develop/contracts/src/v0.8/vrf/dev/SubscriptionAPI.sol
/// @notice License: MIT
abstract contract SubscriptionAPI is ReentrancyGuard, ISubscription {
    using EnumerableSet for EnumerableSet.UintSet;

    // We need to maintain a list of consuming addresses.
    // This bound ensures we are able to loop over them as needed.
    // Should a user require more consumers, they can use multiple subscriptions.
    uint16 public constant MAX_CONSUMERS = 100;

    error TooManyConsumers();
    error InsufficientBalance();
    error InvalidConsumer(uint256 subId, address consumer);
    error InvalidSubscription();
    error InvalidCalldata();
    error MustBeSubOwner(address owner);
    error MustBeRequestedOwner(address proposedOwner);
    error BalanceInvariantViolated(uint256 internalBalance, uint256 externalBalance); // Should never happen
    error FailedToSendNative();
    error IndexOutOfRange();
    error PendingRequestExists();

    // We use the subscription struct (1 word)
    // at fulfillment time.
    struct Subscription {
        // a uint96 is large enough to hold around ~8e28 wei, or 80 billion ether.
        // That should be enough to cover most (if not all) subscriptions.
        uint96 nativeBalance; // Common native balance used for all consumer requests.
        uint64 reqCount;
    }
    // We use the config for the mgmt APIs

    struct SubscriptionConfig {
        address owner; // Owner can fund/withdraw/cancel the sub.
        address requestedOwner; // For safely transferring sub ownership.
        // Maintains the list of keys in s_consumers.
        // We do this for 2 reasons:
        // 1. To be able to clean up all keys from s_consumers when canceling a subscription.
        // 2. To be able to return the list of all consumers in getSubscription.
        // Note that we need the s_consumers map to be able to directly check if a
        // consumer is valid without reading all the consumers from storage.
        address[] consumers;
    }

    struct ConsumerConfig {
        bool active;
        uint64 nonce;
        uint64 pendingReqCount;
    }
    // Note a nonce of 0 indicates the consumer is not assigned to that subscription.

    mapping(address => mapping(uint256 => ConsumerConfig)) /* consumerAddress */ /* subId */ /* consumerConfig */
        internal s_consumers;
    mapping(uint256 => SubscriptionConfig) /* subId */ /* subscriptionConfig */ internal s_subscriptionConfigs;
    mapping(uint256 => Subscription) /* subId */ /* subscription */ internal s_subscriptions;
    // subscription nonce used to construct subId. Rises monotonically
    uint64 public s_currentSubNonce;
    // track all subscription id's that were created by this contract
    // note: access should be through the getActiveSubscriptionIds() view function
    // which takes a starting index and a max number to fetch in order to allow
    // "pagination" of the subscription ids. in the event a very large number of
    // subscription id's are stored in this set, they cannot be retrieved in a
    // single RPC call without violating various size limits.
    EnumerableSet.UintSet internal s_subIds;
    // s_totalNativeBalance tracks the total native sent to/from
    // this contract through fundSubscription, cancelSubscription.
    // A discrepancy with this contract's native balance indicates someone
    // sent native using transfer and so we may need to use recoverNativeFunds.
    uint96 public s_totalNativeBalance;
    // The following variables track fees collected from direct funding requests or
    // subscription based requests that have become withdrawable for contract admin.
    uint96 public s_withdrawableDirectFundingFeeNative;
    uint96 public s_withdrawableSubscriptionFeeNative;

    event SubscriptionCreated(uint256 indexed subId, address owner);
    event SubscriptionFundedWithNative(uint256 indexed subId, uint256 oldNativeBalance, uint256 newNativeBalance);
    event SubscriptionConsumerAdded(uint256 indexed subId, address consumer);
    event SubscriptionConsumerRemoved(uint256 indexed subId, address consumer);
    event SubscriptionCanceled(uint256 indexed subId, address to, uint256 amountNative);
    event SubscriptionOwnerTransferRequested(uint256 indexed subId, address from, address to);
    event SubscriptionOwnerTransferred(uint256 indexed subId, address from, address to);

    struct Config {
        uint32 maxGasLimit;
        // Gas to cover oracle payment after we calculate the payment.
        // We make it configurable in case those operations are repriced.
        // The recommended number is below, though it may vary slightly
        // if certain chains do not implement certain EIP's.
        // 21000 + // base cost of the transaction
        // 100 + 5000 + // warm subscription balance read and update. See https://eips.ethereum.org/EIPS/eip-2929
        // 2*2100 + 5000 - // cold read oracle address and oracle balance and first time oracle balance update, note first time will be 20k, but 5k subsequently
        // 4800 + // request delete refund (refunds happen after execution), note pre-london fork was 15k. See https://eips.ethereum.org/EIPS/eip-3529
        // 6685 + // Positive static costs of argument encoding etc. note that it varies by +/- x*12 for every x bytes of non-zero data in the proof.
        // Total: 37,185 gas.
        uint32 gasAfterPaymentCalculation;
        // Flat fee charged per fulfillment in millionths of native.
        // So fee range is [0, 2^32/10^6].
        uint32 fulfillmentFlatFeeNativePPM;
        // Wei charged per unit of gas for callback operations
        uint32 weiPerUnitGas;
        uint32 blsPairingCheckOverhead;
        // nativePremiumPercentage is the percentage of the total gas costs that is added to the final premium for native payment
        // nativePremiumPercentage = 10 means 10% of the total gas costs is added. only integral percentage is allowed
        uint8 nativePremiumPercentage;
        // Gas required for exact EXTCODESIZE call and additional operations in CallWithExactGas library
        uint32 gasForCallExactCheck;
    }

    Config public s_config;

    modifier onlySubOwner(uint256 subId) {
        _onlySubOwner(subId);
        _;
    }

    function _requireSufficientBalance(bool condition) internal pure {
        if (!condition) {
            revert InsufficientBalance();
        }
    }

    function _requireValidSubscription(address subOwner) internal pure {
        if (subOwner == address(0)) {
            revert InvalidSubscription();
        }
    }

    /**
     * @inheritdoc ISubscription
     */
    function fundSubscriptionWithNative(uint256 subId) external payable override nonReentrant {
        _requireValidSubscription(s_subscriptionConfigs[subId].owner);
        // We do not check that the msg.sender is the subscription owner,
        // anyone can fund a subscription.
        // We also do not check that msg.value > 0, since that's just a no-op
        // and would be a waste of gas on the caller's part.
        uint256 oldNativeBalance = s_subscriptions[subId].nativeBalance;
        s_subscriptions[subId].nativeBalance += uint96(msg.value);
        s_totalNativeBalance += uint96(msg.value);
        emit SubscriptionFundedWithNative(subId, oldNativeBalance, oldNativeBalance + msg.value);
    }

    /**
     * @inheritdoc ISubscription
     */
    function getSubscription(uint256 subId)
        public
        view
        override
        returns (uint96 nativeBalance, uint64 reqCount, address subOwner, address[] memory consumers)
    {
        subOwner = s_subscriptionConfigs[subId].owner;
        _requireValidSubscription(subOwner);
        return (
            s_subscriptions[subId].nativeBalance,
            s_subscriptions[subId].reqCount,
            subOwner,
            s_subscriptionConfigs[subId].consumers
        );
    }

    /**
     * @inheritdoc ISubscription
     */
    function getActiveSubscriptionIds(uint256 startIndex, uint256 maxCount)
        external
        view
        override
        returns (uint256[] memory ids)
    {
        uint256 numSubs = s_subIds.length();
        if (startIndex >= numSubs) revert IndexOutOfRange();
        uint256 endIndex = startIndex + maxCount;
        endIndex = endIndex > numSubs || maxCount == 0 ? numSubs : endIndex;
        uint256 idsLength = endIndex - startIndex;
        ids = new uint256[](idsLength);
        for (uint256 idx = 0; idx < idsLength; ++idx) {
            ids[idx] = s_subIds.at(idx + startIndex);
        }
        return ids;
    }

    /**
     * @inheritdoc ISubscription
     */
    function createSubscription() external override nonReentrant returns (uint256 subId) {
        // Generate a subscription id that is globally unique.
        uint64 currentSubNonce = s_currentSubNonce;
        subId = uint256(
            keccak256(abi.encodePacked(msg.sender, blockhash(block.number - 1), address(this), currentSubNonce))
        );
        // Increment the subscription nonce counter.
        s_currentSubNonce = currentSubNonce + 1;
        // Initialize storage variables.
        address[] memory consumers = new address[](0);
        s_subscriptions[subId] = Subscription({nativeBalance: 0, reqCount: 0});
        s_subscriptionConfigs[subId] =
            SubscriptionConfig({owner: msg.sender, requestedOwner: address(0), consumers: consumers});
        // Update the s_subIds set, which tracks all subscription ids created in this contract.
        s_subIds.add(subId);

        emit SubscriptionCreated(subId, msg.sender);
    }

    /// @notice Checks if there are any pending decryption requests for a given subscription.
    /// @dev Iterates through all consumers of the subscription to check for pending requests.
    /// @param subId The subscription ID to check for pending requests.
    /// @return True if at least one consumer has a pending request, otherwise false.
    function pendingRequestExists(uint256 subId) public view override returns (bool) {
        address[] storage consumers = s_subscriptionConfigs[subId].consumers;
        uint256 consumersLength = consumers.length;
        for (uint256 i = 0; i < consumersLength; ++i) {
            if (s_consumers[consumers[i]][subId].pendingReqCount > 0) {
                return true;
            }
        }
        return false;
    }

    /// @notice Cancels a subscription and sends remaining funds to the specified address.
    /// @dev Ensures there are no pending decryption requests before cancellation.
    ///      Only the subscription owner can call this function.
    /// @param subId The subscription ID to cancel.
    /// @param to The address where remaining funds should be sent.
    /// @custom:error PendingRequestExists Thrown if there are pending decryption requests for the subscription.
    function cancelSubscription(uint256 subId, address to) external override onlySubOwner(subId) nonReentrant {
        if (pendingRequestExists(subId)) {
            revert PendingRequestExists();
        }
        _cancelSubscriptionHelper(subId, to);
    }

    /// @notice Removes a consumer from a subscription.
    /// @dev Only the subscription owner can call this function.
    ///      Ensures there are no pending requests before removing the consumer.
    ///      The consumer is removed by swapping with the last element in the array and then popping.
    /// @param subId The subscription ID from which the consumer will be removed.
    /// @param consumer The address of the consumer to remove.
    /// @custom:error PendingRequestExists Thrown if there are pending decryption requests for the subscription.
    /// @custom:error InvalidConsumer Thrown if the consumer is not active under the subscription.
    /// @custom:event SubscriptionConsumerRemoved Emitted when a consumer is successfully removed.
    function removeConsumer(uint256 subId, address consumer) external override onlySubOwner(subId) nonReentrant {
        if (pendingRequestExists(subId)) {
            revert PendingRequestExists();
        }
        if (!s_consumers[consumer][subId].active) {
            revert InvalidConsumer(subId, consumer);
        }

        // Remove consumer from subscription list
        address[] storage s_subscriptionConsumers = s_subscriptionConfigs[subId].consumers;
        uint256 consumersLength = s_subscriptionConsumers.length;
        for (uint256 i = 0; i < consumersLength; ++i) {
            if (s_subscriptionConsumers[i] == consumer) {
                s_subscriptionConsumers[i] = s_subscriptionConsumers[consumersLength - 1]; // Swap with last element
                s_subscriptionConsumers.pop(); // Remove last element
                break;
            }
        }

        s_consumers[consumer][subId].active = false;
        emit SubscriptionConsumerRemoved(subId, consumer);
    }

    /**
     * @inheritdoc ISubscription
     */
    function requestSubscriptionOwnerTransfer(uint256 subId, address newOwner)
        external
        override
        onlySubOwner(subId)
        nonReentrant
    {
        // Proposing to address(0) would never be claimable so don't need to check.
        SubscriptionConfig storage subscriptionConfig = s_subscriptionConfigs[subId];
        if (subscriptionConfig.requestedOwner != newOwner) {
            subscriptionConfig.requestedOwner = newOwner;
            emit SubscriptionOwnerTransferRequested(subId, msg.sender, newOwner);
        }
    }

    /**
     * @inheritdoc ISubscription
     */
    function acceptSubscriptionOwnerTransfer(uint256 subId) external override nonReentrant {
        address oldOwner = s_subscriptionConfigs[subId].owner;
        _requireValidSubscription(oldOwner);
        if (s_subscriptionConfigs[subId].requestedOwner != msg.sender) {
            revert MustBeRequestedOwner(s_subscriptionConfigs[subId].requestedOwner);
        }
        s_subscriptionConfigs[subId].owner = msg.sender;
        s_subscriptionConfigs[subId].requestedOwner = address(0);
        emit SubscriptionOwnerTransferred(subId, oldOwner, msg.sender);
    }

    /**
     * @inheritdoc ISubscription
     */
    function addConsumer(uint256 subId, address consumer) external override onlySubOwner(subId) nonReentrant {
        ConsumerConfig storage consumerConfig = s_consumers[consumer][subId];
        if (consumerConfig.active) {
            // Idempotence - do nothing if already added.
            // Ensures uniqueness in s_subscriptions[subId].consumers.
            return;
        }
        // Already maxed, cannot add any more consumers.
        address[] storage consumers = s_subscriptionConfigs[subId].consumers;
        if (consumers.length == MAX_CONSUMERS) {
            revert TooManyConsumers();
        }
        // consumerConfig.nonce is 0 if the consumer had never sent a request to this subscription
        // otherwise, consumerConfig.nonce is non-zero
        // in both cases, use consumerConfig.nonce as is and set active status to true
        consumerConfig.active = true;
        consumers.push(consumer);

        emit SubscriptionConsumerAdded(subId, consumer);
    }

    function _deleteSubscription(uint256 subId) internal returns (uint96 nativeBalance) {
        address[] storage consumers = s_subscriptionConfigs[subId].consumers;
        nativeBalance = s_subscriptions[subId].nativeBalance;
        // Note bounded by MAX_CONSUMERS;
        // If no consumers, does nothing.
        uint256 consumersLength = consumers.length;
        for (uint256 i = 0; i < consumersLength; ++i) {
            delete s_consumers[consumers[i]][subId];
        }
        delete s_subscriptionConfigs[subId];
        delete s_subscriptions[subId];
        s_subIds.remove(subId);
        if (nativeBalance != 0) {
            s_totalNativeBalance -= nativeBalance;
        }
    }

    function _cancelSubscriptionHelper(uint256 subId, address to) internal {
        (uint96 nativeBalance) = _deleteSubscription(subId);

        // send native to the "to" address using call
        _mustSendNative(to, uint256(nativeBalance));
        emit SubscriptionCanceled(subId, to, nativeBalance);
    }

    function _onlySubOwner(uint256 subId) internal view {
        address subOwner = s_subscriptionConfigs[subId].owner;
        _requireValidSubscription(subOwner);
        if (msg.sender != subOwner) {
            revert MustBeSubOwner(subOwner);
        }
    }

    function _mustSendNative(address to, uint256 amount) internal {
        (bool success,) = to.call{value: amount}("");
        if (!success) {
            revert FailedToSendNative();
        }
    }
}
