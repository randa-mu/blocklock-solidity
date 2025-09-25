# MockBlocklockSender

A simplified mock implementation of the BlocklockSender contract for testing blocklock functionality without the complexity of real cryptographic operations, upgrades, or access controls.

## Overview

The MockBlocklockSender allows you to test blocklock workflows by providing:
- **Manual request fulfillment** for deterministic testing
- **Simple XOR-based encryption/decryption** for predictable results  
- **Complete subscription management** via ISubscription interface
- **Easy ciphertext generation** with helper functions

## Key Features

### 🔄 Blocklock Request Flow
1. **Request**: Submit blocklock requests with encrypted data
2. **Track**: Monitor pending requests 
3. **Fulfill**: Manually provide decryption keys for testing
4. **Callback**: Automatic callback to requesting contract

### 🔐 Mock Encryption
- Uses simple XOR operation: `ciphertext = plaintext XOR key`
- Decryption reverses it: `plaintext = ciphertext XOR key`
- Completely predictable for test scenarios

### 💰 Subscription Support
- Create and manage subscriptions
- Add/remove consumers
- Fund subscriptions with native tokens
- Transfer ownership

## Basic Usage

### 1. Deploy Contract
```solidity
MockBlocklockSender mockSender = new MockBlocklockSender();
```

### 2. Create Test Data
```solidity
// Your secret auction price
uint256 auctionPrice = 1500 ether;
bytes memory priceData = mockSender.encodePrice(auctionPrice);

// Secret key for decryption
bytes memory decryptionKey = "auction-secret-2024";

// Generate blinded ciphertext
TypesLib.Ciphertext memory blindedPrice = mockSender.generateSimpleMockCiphertext(
    priceData,
    decryptionKey
);
```

### 3. Submit Blocklock Request
```solidity
// Direct payment method
uint256 requestId = mockSender.requestBlocklock{value: 0.001 ether}(
    100000,                    // callback gas limit
    "block.number > 100",      // unlock condition
    blindedPrice               // encrypted auction price
);

// OR with subscription
uint256 subId = mockSender.createSubscription();
mockSender.addConsumer(subId, address(this));
mockSender.fundSubscriptionWithNative{value: 1 ether}(subId);

uint256 requestId = mockSender.requestBlocklockWithSubscription(
    100000,
    subId,
    "block.number > 100",
    blindedPrice
);
```

### 4. Fulfill Request (Manual Testing)
```solidity
// Check pending requests
uint256[] memory pending = mockSender.getPendingRequestIds();

// Manually fulfill when condition is met
mockSender.fulfillRequest(
    requestId,
    decryptionKey,          // provide the secret key
    "dummy-signature"       // mock signature
);
```

### 5. Verify Decryption
```solidity
// Get the fulfilled request
TypesLib.BlocklockRequest memory request = mockSender.getRequest(requestId);

// Decrypt the data
bytes memory decryptedData = mockSender.decrypt(blindedPrice, request.decryptionKey);
uint256 revealedPrice = mockSender.decodePrice(decryptedData);

assert(revealedPrice == auctionPrice); // ✅ Should match original
```

## Test Scenarios

### Sealed Bid Auction
```solidity
function testSealedBidAuction() public {
    // Bidder creates encrypted bid
    uint256 bidAmount = 2000 ether;
    bytes memory key = "bidder1-secret";
    TypesLib.Ciphertext memory encryptedBid = mockSender.generateSimpleMockCiphertext(
        mockSender.encodePrice(bidAmount),
        key
    );
    
    // Submit blocklock request (bid reveal after auction ends)
    uint256 requestId = mockSender.requestBlocklock{value: 0.001 ether}(
        200000,
        "block.number > auctionEndBlock",
        encryptedBid
    );
    
    // Simulate auction end - fulfill request
    vm.roll(auctionEndBlock + 1);
    mockSender.fulfillRequest(requestId, key, "sig");
    
    // Verify bid was revealed correctly
    bytes memory revealed = mockSender.decrypt(encryptedBid, key);
    uint256 revealedBid = mockSender.decodePrice(revealed);
    assertEq(revealedBid, bidAmount);
}
```

### Subscription-Based Usage
```solidity
function testSubscriptionWorkflow() public {
    // Setup subscription
    uint256 subId = mockSender.createSubscription();
    mockSender.addConsumer(subId, bidderContract);
    mockSender.fundSubscriptionWithNative{value: 10 ether}(subId);
    
    // Multiple requests using subscription
    for (uint i = 0; i < 5; i++) {
        vm.prank(bidderContract);
        uint256 requestId = mockSender.requestBlocklockWithSubscription(
            100000,
            subId,
            abi.encodePacked("condition", i),
            generateTestCiphertext(i)
        );
    }
    
    // Fulfill all pending
    uint256[] memory pending = mockSender.getPendingRequestIds();
    for (uint i = 0; i < pending.length; i++) {
        mockSender.fulfillRequest(pending[i], "key", "sig");
    }
}
```

## API Reference

### Core Functions
- `requestBlocklock()` - Submit request with direct payment
- `requestBlocklockWithSubscription()` - Submit request using subscription
- `fulfillRequest()` - Manually fulfill pending request
- `getPendingRequestIds()` - Get all pending request IDs
- `getRequest()` - Get request details
- `isInFlight()` - Check if request is pending

### Helper Functions
- `generateSimpleMockCiphertext()` - Create test ciphertext
- `encodePrice()` / `decodePrice()` - Handle price encoding
- `decrypt()` - Decrypt ciphertext with key

### Subscription Management
- `createSubscription()` - Create new subscription
- `addConsumer()` / `removeConsumer()` - Manage consumers
- `fundSubscriptionWithNative()` - Add funds
- `cancelSubscription()` - Cancel and withdraw
- `getSubscription()` - Get subscription details

## Configuration
```solidity
mockSender.setMaxGasLimit(5000000);     // Set gas limits
mockSender.setDisabled(false);          // Enable/disable contract
```

## Benefits for Testing

✅ **Deterministic**: XOR encryption gives predictable results  
✅ **Fast**: No complex cryptography - instant execution  
✅ **Observable**: Events and state for easy verification  
✅ **Complete**: Full subscription and request lifecycle  
✅ **Isolated**: No external dependencies or oracles  

Perfect for unit tests, integration tests, and auction simulation scenarios!