// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

/// @notice ISubscription interface
/// @notice interface for contracts supporting user subscription for an onchain service.
/// @notice Inspired by Chainlink's IVRFSubscriptionV2Plus. Source code at: https://github.com/smartcontractkit/chainlink/blob/develop/contracts/src/v0.8/vrf/dev/interfaces/IVRFSubscriptionV2Plus.sol
/// @notice License: MIT
interface ISubscription {
    /// @notice Add a consumer to a subscription.
    /// @param subId - ID of the subscription
    /// @param consumer - New consumer which can use the subscription
    function addConsumer(uint256 subId, address consumer) external;

    /// @notice Remove a consumer from a subscription.
    /// @param subId - ID of the subscription
    /// @param consumer - Consumer to remove from the subscription
    function removeConsumer(uint256 subId, address consumer) external;

    /// @notice Cancel a subscription
    /// @param subId - ID of the subscription
    /// @param to - Where to send the remaining subscription balance to
    function cancelSubscription(uint256 subId, address to) external;

    /// @notice Accept subscription owner transfer.
    /// @param subId - ID of the subscription
    /// @dev will revert if original owner of subId has
    /// not requested that msg.sender become the new owner.
    function acceptSubscriptionOwnerTransfer(uint256 subId) external;

    /// @notice Request subscription owner transfer.
    /// @param subId - ID of the subscription
    /// @param newOwner - proposed new owner of the subscription
    function requestSubscriptionOwnerTransfer(uint256 subId, address newOwner) external;

    /// @notice Create a subscription.
    /// @return subId - A unique subscription id.
    /// @dev You can manage the consumer set dynamically with addConsumer/removeConsumer.
    /// @dev Note to fund the subscription with Native, use fundSubscriptionWithNative. Be sure
    /// @dev  to send Native with the call, for example:
    /// @dev COORDINATOR.fundSubscriptionWithNative{value: amount}(subId);
    function createSubscription() external returns (uint256 subId);

    /// @notice Get a subscription.
    /// @param subId - ID of the subscription
    /// @return nativeBalance - native balance of the subscription in wei.
    /// @return reqCount - Requests count of subscription.
    /// @return owner - owner of the subscription.
    /// @return consumers - list of consumer address which are able to use this subscription.
    function getSubscription(uint256 subId)
        external
        view
        returns (uint96 nativeBalance, uint64 reqCount, address owner, address[] memory consumers);

    /// @notice Check to see if there exists a request commitment consumers
    /// for all consumers and keyhashes for a given sub.
    /// @param subId - ID of the subscription
    /// @return true if there exists at least one unfulfilled request for the subscription, false
    /// otherwise.
    function pendingRequestExists(uint256 subId) external view returns (bool);

    /// @notice Paginate through all active subscriptions.
    /// @param startIndex index of the subscription to start from
    /// @param maxCount maximum number of subscriptions to return, 0 to return all
    /// @dev the order of IDs in the list is///*not guaranteed**, therefore, if making successive calls, one
    /// @dev should consider keeping the blockheight constant to ensure a holistic picture of the contract state
    function getActiveSubscriptionIds(uint256 startIndex, uint256 maxCount) external view returns (uint256[] memory);

    /// @notice Fund a subscription with native.
    /// @param subId - ID of the subscription
    /// @notice This method expects msg.value to be greater than or equal to 0.
    function fundSubscriptionWithNative(uint256 subId) external payable;
}
