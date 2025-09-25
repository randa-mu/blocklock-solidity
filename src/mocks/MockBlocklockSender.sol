// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import "src/libraries/TypesLib.sol";
import {IBlocklockSender} from "src/interfaces/IBlocklockSender.sol";
import {ISubscription} from "src/interfaces/ISubscription.sol";
import {IBlocklockReceiver} from "src/interfaces/IBlocklockReceiver.sol";

/// @title MockBlocklockSender Contract
/// @notice Simplified mock version for testing blocklock functionality
/// @dev Allows manual fulfillment of blocklock requests and subscription management
contract MockBlocklockSender is IBlocklockSender {
    
    // Subscription structures
    struct Subscription {
        uint96 nativeBalance;
        uint64 reqCount;
        address[] consumers;
    }
    
    struct SubscriptionConfig {
        address owner;
        address requestedOwner;
    }
    
    struct ConsumerConfig {
        bool active;
        uint64 nonce;
        uint64 pendingReqCount;
    }

    /// @notice Counter for generating unique request IDs
    uint256 private requestIdCounter;
    
    /// @notice Counter for generating unique subscription IDs
    uint256 private subscriptionIdCounter;

    /// @notice Mapping from request ID to blocklock request
    mapping(uint256 => TypesLib.BlocklockRequest) public blocklockRequests;

    /// @notice Mapping to track pending requests for manual fulfillment
    mapping(uint256 => bool) public pendingRequests;

    /// @notice Array to store all pending request IDs
    uint256[] public pendingRequestIds;

    /// @notice Subscription data
    mapping(uint256 => Subscription) public subscriptions;
    mapping(uint256 => SubscriptionConfig) public subscriptionConfigs;
    mapping(address => mapping(uint256 => ConsumerConfig)) public consumers;

    /// @notice Basic configuration
    uint32 public maxGasLimit = 2500000;
    bool public disabled = false;

    /// @notice Events
    event BlocklockRequested(
        uint256 indexed requestId,
        bytes condition,
        TypesLib.Ciphertext ciphertext,
        address indexed requester,
        uint256 requestedAt
    );

    event BlocklockCallbackSuccess(
        uint256 indexed requestId, 
        bytes condition, 
        TypesLib.Ciphertext ciphertext, 
        bytes decryptionKey
    );

    event BlocklockCallbackFailed(uint256 indexed requestId);

    event ManualFulfillment(uint256 indexed requestId, bytes decryptionKey, bytes signature);

    constructor() {
        requestIdCounter = 1;
        subscriptionIdCounter = 1;
    }

    /// @notice Requests a blocklock without subscription ID
    function requestBlocklock(
        uint32 callbackGasLimit,
        bytes calldata condition,
        TypesLib.Ciphertext calldata ciphertext
    ) external payable returns (uint256) {
        require(!disabled, "Contract is disabled");
        require(callbackGasLimit <= maxGasLimit, "Gas limit too high");
        require(msg.value > 0, "Payment required for direct funding");

        uint256 requestId = requestIdCounter++;

        blocklockRequests[requestId] = TypesLib.BlocklockRequest({
            subId: 0,
            directFundingFeePaid: msg.value,
            callbackGasLimit: callbackGasLimit,
            decryptionRequestId: requestId,
            condition: condition,
            ciphertext: ciphertext,
            signature: hex"",
            decryptionKey: hex"",
            callback: msg.sender
        });

        pendingRequests[requestId] = true;
        pendingRequestIds.push(requestId);

        emit BlocklockRequested(requestId, condition, ciphertext, msg.sender, block.timestamp);
        return requestId;
    }

    /// @notice Requests a blocklock with subscription ID
    function requestBlocklockWithSubscription(
        uint32 callbackGasLimit,
        uint256 subId,
        bytes memory condition,
        TypesLib.Ciphertext calldata ciphertext
    ) public payable returns (uint256) {
        require(!disabled, "Contract is disabled");
        require(callbackGasLimit <= maxGasLimit, "Gas limit too high");
        
        if (subId > 0) {
            require(subscriptionConfigs[subId].owner != address(0), "Invalid subscription");
            require(consumers[msg.sender][subId].active, "Consumer not active");
            
            // Update consumer state
            consumers[msg.sender][subId].nonce++;
            consumers[msg.sender][subId].pendingReqCount++;
        } else {
            require(msg.value > 0, "Payment required for direct funding");
        }

        uint256 requestId = requestIdCounter++;

        blocklockRequests[requestId] = TypesLib.BlocklockRequest({
            subId: subId,
            directFundingFeePaid: msg.value,
            callbackGasLimit: callbackGasLimit,
            decryptionRequestId: requestId,
            condition: condition,
            ciphertext: ciphertext,
            signature: hex"",
            decryptionKey: hex"",
            callback: msg.sender
        });

        pendingRequests[requestId] = true;
        pendingRequestIds.push(requestId);

        emit BlocklockRequested(requestId, condition, ciphertext, msg.sender, block.timestamp);
        return requestId;
    }

    /// @notice Manually fulfill a blocklock request
    /// @param requestId The ID of the request to fulfill
    /// @param decryptionKey The decryption key to provide
    /// @param signature The signature for the decryption key
    function fulfillRequest(uint256 requestId, bytes calldata decryptionKey, bytes calldata signature) external {
        require(pendingRequests[requestId], "Request not pending or doesn't exist");
        
        TypesLib.BlocklockRequest storage request = blocklockRequests[requestId];
        
        // Remove from pending
        pendingRequests[requestId] = false;
        _removePendingRequestId(requestId);

        // Store decryption data
        request.decryptionKey = decryptionKey;
        request.signature = signature;

        // Call the callback
        try IBlocklockReceiver(request.callback).receiveBlocklock(requestId, decryptionKey) {
            emit BlocklockCallbackSuccess(requestId, request.condition, request.ciphertext, decryptionKey);
        } catch {
            emit BlocklockCallbackFailed(requestId);
        }

        // Update subscription state if needed
        if (request.subId > 0) {
            subscriptions[request.subId].reqCount++;
            consumers[request.callback][request.subId].pendingReqCount--;
        }

        emit ManualFulfillment(requestId, decryptionKey, signature);
    }

    /// @notice Get all pending request IDs
    function getPendingRequestIds() external view returns (uint256[] memory) {
        uint256 count = 0;
        for (uint256 i = 0; i < pendingRequestIds.length; i++) {
            if (pendingRequests[pendingRequestIds[i]]) {
                count++;
            }
        }

        uint256[] memory activePending = new uint256[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < pendingRequestIds.length; i++) {
            if (pendingRequests[pendingRequestIds[i]]) {
                activePending[index] = pendingRequestIds[i];
                index++;
            }
        }

        return activePending;
    }

    /// @notice Get request details
    function getRequest(uint256 requestId) external view returns (TypesLib.BlocklockRequest memory) {
        require(blocklockRequests[requestId].decryptionRequestId != 0, "Request doesn't exist");
        return blocklockRequests[requestId];
    }

    /// @notice Check if request is still pending
    function isInFlight(uint256 requestId) external view returns (bool) {
        return pendingRequests[requestId];
    }

    /// @notice Internal function to remove request ID from pending array
    function _removePendingRequestId(uint256 requestId) internal {
        for (uint256 i = 0; i < pendingRequestIds.length; i++) {
            if (pendingRequestIds[i] == requestId) {
                pendingRequestIds[i] = pendingRequestIds[pendingRequestIds.length - 1];
                pendingRequestIds.pop();
                break;
            }
        }
    }

    /// @notice Set maximum gas limit
    function setMaxGasLimit(uint32 _maxGasLimit) external {
        maxGasLimit = _maxGasLimit;
    }

    /// @notice Disable/enable the contract
    function setDisabled(bool _disabled) external {
        disabled = _disabled;
    }

    // ISubscription implementation
    function createSubscription() external override returns (uint256 subId) {
        subId = subscriptionIdCounter++;
        
        subscriptions[subId] = Subscription({
            nativeBalance: 0,
            reqCount: 0,
            consumers: new address[](0)
        });
        
        subscriptionConfigs[subId] = SubscriptionConfig({
            owner: msg.sender,
            requestedOwner: address(0)
        });
        
        return subId;
    }

    function addConsumer(uint256 subId, address consumer) external override {
        require(subscriptionConfigs[subId].owner == msg.sender, "Only owner can add consumers");
        require(subscriptionConfigs[subId].owner != address(0), "Invalid subscription");
        
        if (consumers[consumer][subId].active) {
            return; // Already active
        }

        consumers[consumer][subId] = ConsumerConfig({
            active: true,
            nonce: 1,
            pendingReqCount: 0
        });

        subscriptions[subId].consumers.push(consumer);
    }

    function removeConsumer(uint256 subId, address consumer) external override {
        require(subscriptionConfigs[subId].owner == msg.sender, "Only owner can remove consumers");
        require(consumers[consumer][subId].pendingReqCount == 0, "Consumer has pending requests");

        if (!consumers[consumer][subId].active) {
            return; // Already inactive
        }

        consumers[consumer][subId].active = false;

        // Remove from consumers array
        address[] storage consumerArray = subscriptions[subId].consumers;
        for (uint256 i = 0; i < consumerArray.length; i++) {
            if (consumerArray[i] == consumer) {
                consumerArray[i] = consumerArray[consumerArray.length - 1];
                consumerArray.pop();
                break;
            }
        }
    }

    function cancelSubscription(uint256 subId, address to) external override {
        require(subscriptionConfigs[subId].owner == msg.sender, "Only owner can cancel");
        require(to != address(0), "Invalid recipient");

        uint96 balance = subscriptions[subId].nativeBalance;
        
        // Clear subscription data
        delete subscriptions[subId];
        delete subscriptionConfigs[subId];

        // Send remaining balance
        if (balance > 0) {
            payable(to).transfer(balance);
        }
    }

    function fundSubscriptionWithNative(uint256 subId) external payable override {
        require(subscriptionConfigs[subId].owner != address(0), "Invalid subscription");
        
        subscriptions[subId].nativeBalance += uint96(msg.value);
    }

    function getSubscription(uint256 subId)
        external
        view
        override
        returns (uint96 nativeBalance, uint64 reqCount, address owner, address[] memory consumerList)
    {
        require(subscriptionConfigs[subId].owner != address(0), "Invalid subscription");
        
        return (
            subscriptions[subId].nativeBalance,
            subscriptions[subId].reqCount,
            subscriptionConfigs[subId].owner,
            subscriptions[subId].consumers
        );
    }

    function requestSubscriptionOwnerTransfer(uint256 subId, address newOwner) external override {
        require(subscriptionConfigs[subId].owner == msg.sender, "Only owner can transfer");
        require(newOwner != address(0), "Invalid new owner");
        
        subscriptionConfigs[subId].requestedOwner = newOwner;
    }

    function acceptSubscriptionOwnerTransfer(uint256 subId) external override {
        require(subscriptionConfigs[subId].requestedOwner == msg.sender, "Not requested owner");
        
        subscriptionConfigs[subId].owner = msg.sender;
        subscriptionConfigs[subId].requestedOwner = address(0);
    }

    function pendingRequestExists(uint256 subId) external view override returns (bool) {
        require(subscriptionConfigs[subId].owner != address(0), "Invalid subscription");
        
        address[] memory consumerList = subscriptions[subId].consumers;
        for (uint256 i = 0; i < consumerList.length; i++) {
            if (consumers[consumerList[i]][subId].pendingReqCount > 0) {
                return true;
            }
        }
        return false;
    }

    function getActiveSubscriptionIds(uint256 startIndex, uint256 maxCount) 
        external 
        view 
        override 
        returns (uint256[] memory) 
    {
        uint256 totalSubs = subscriptionIdCounter - 1;
        if (startIndex > totalSubs) {
            return new uint256[](0);
        }
        
        uint256 endIndex = maxCount == 0 ? totalSubs : startIndex + maxCount - 1;
        if (endIndex > totalSubs) {
            endIndex = totalSubs;
        }
        
        uint256[] memory activeIds = new uint256[](endIndex - startIndex + 1);
        uint256 count = 0;
        
        for (uint256 i = startIndex; i <= endIndex; i++) {
            if (subscriptionConfigs[i].owner != address(0)) {
                activeIds[count] = i;
                count++;
            }
        }
        
        // Resize to actual count
        uint256[] memory result = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = activeIds[i];
        }
        
        return result;
    }

    // Required IBlocklockSender functions (simplified implementations)
    function estimateRequestPriceNative(uint32, uint256) external pure returns (uint256) {
        return 0.001 ether; // Simple fixed price
    }

    function calculateRequestPriceNative(uint32) external pure returns (uint256) {
        return 0.001 ether; // Simple fixed price
    }

    /// @notice Simple mock decryption - just XOR the key with the ciphertext.v
    /// @dev In a real implementation, this would do proper BLS decryption
    /// For testing, we just do a simple XOR operation
    function decrypt(TypesLib.Ciphertext calldata ciphertext, bytes calldata decryptionKey)
        external
        pure
        returns (bytes memory)
    {
        // Simple mock implementation: XOR the key with ciphertext.v to get "decrypted" data
        bytes memory result = new bytes(decryptionKey.length);
        
        for (uint256 i = 0; i < decryptionKey.length && i < ciphertext.v.length; i++) {
            result[i] = ciphertext.v[i] ^ decryptionKey[i];
        }
        
        // If key is longer than v, just use the remaining key bytes
        for (uint256 i = ciphertext.v.length; i < decryptionKey.length; i++) {
            result[i] = decryptionKey[i];
        }
        
        return result;
    }

    /// @notice Get current chain ID
    function getChainId() external view returns (uint256 chainId) {
        assembly {
            chainId := chainid()
        }
    }

    /// @notice Set decryption sender (no-op for mock, but required by interface)
    /// @dev In the real implementation, this would set the decryption service
    /// For mock purposes, we just emit an event to track calls
    function setDecryptionSender(address newDecryptionSender) external {
        // For mock purposes, just emit an event - no actual functionality needed
        // In tests, you can verify this was called if needed
        emit DecryptionSenderSet(newDecryptionSender);
    }

    /// @notice Event for tracking setDecryptionSender calls in tests
    event DecryptionSenderSet(address indexed newDecryptionSender);

    /// @notice Helper function to generate mock ciphertext for testing
    /// @dev Creates ciphertext by XORing plaintext with decryption key
    /// @param plaintext The original data to encrypt (e.g., auction price)
    /// @param decryptionKey The key that will later decrypt this data
    /// @param dummyU Dummy value for the U field (can be any G2 point for testing)
    /// @return ciphertext The generated ciphertext that can be decrypted with the same key
    function generateMockCiphertext(
        bytes calldata plaintext,
        bytes calldata decryptionKey,
        BLS.PointG2 memory dummyU
    ) public pure returns (TypesLib.Ciphertext memory ciphertext) {
        
        // Create V by XORing plaintext with decryption key
        bytes memory v = new bytes(decryptionKey.length);
        for (uint256 i = 0; i < decryptionKey.length; i++) {
            if (i < plaintext.length) {
                v[i] = plaintext[i] ^ decryptionKey[i];
            } else {
                v[i] = decryptionKey[i]; // If key is longer than plaintext
            }
        }
        
        return TypesLib.Ciphertext({
            u: dummyU,     // Dummy G2 point (not used in mock decryption)
            v: v,          // XOR of plaintext and key
            w: plaintext   // Store original plaintext for easy verification
        });
    }

    /// @notice Simplified helper for generating ciphertext with default dummy U
    /// @dev Creates ciphertext with a zero G2 point (fine for testing)
    /// @param plaintext The data to "encrypt" 
    /// @param decryptionKey The key for later decryption
    /// @return ciphertext The mock ciphertext
    function generateSimpleMockCiphertext(
        bytes calldata plaintext,
        bytes calldata decryptionKey
    ) external pure returns (TypesLib.Ciphertext memory ciphertext) {
        
        // Create dummy G2 point (all zeros - fine for mock)
        BLS.PointG2 memory dummyU = BLS.PointG2({
            x: [uint256(0), uint256(0)],
            y: [uint256(0), uint256(0)]
        });
        
        return generateMockCiphertext(plaintext, decryptionKey, dummyU);
    }

    /// @notice Helper to encode auction price as bytes
    /// @param price The auction price to encode
    /// @return Encoded price as bytes
    function encodePrice(uint256 price) external pure returns (bytes memory) {
        return abi.encodePacked(price);
    }

    /// @notice Helper to decode auction price from bytes
    /// @param data The encoded price data
    /// @return The decoded price
    function decodePrice(bytes calldata data) external pure returns (uint256) {
        require(data.length >= 32, "Invalid price data");
        return abi.decode(data, (uint256));
    }

    /// @notice Contract version
    function version() external pure returns (string memory) {
        return "1.0.0-mock";
    }
}