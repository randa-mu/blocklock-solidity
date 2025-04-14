// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {console} from "forge-std/Test.sol";

import {
    Deployment,
    SignatureSchemeAddressProvider,
    BlocklockSender,
    BlocklockSignatureScheme,
    DecryptionSender,
    MockBlocklockReceiver
} from "./Deployment.t.sol";

import {TypesLib, BLS} from "./Base.t.sol";

/// @title BlocklockTest test contract
/// @dev Onchain conditional encryption tests
contract BlocklockTest is Deployment {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    SignatureSchemeAddressProvider internal signatureSchemeAddressProvider;
    BlocklockSignatureScheme internal blocklockScheme;
    DecryptionSender internal decryptionSender;
    BlocklockSender internal blocklockSender;
    MockBlocklockReceiver internal mockBlocklockReceiver;

    function setUp() public override {
        // setup base test
        super.setUp();

        (signatureSchemeAddressProvider, blocklockScheme, decryptionSender, blocklockSender, mockBlocklockReceiver) =
            deployContracts();
    }

    function test_DeploymentConfigurations() public view {
        assertTrue(decryptionSender.hasRole(ADMIN_ROLE, admin));

        assert(address(signatureSchemeAddressProvider) != address(0));
        assert(address(blocklockScheme) != address(0));
        assert(address(decryptionSender) != address(0));
        assert(address(blocklockSender) != address(0));
        assert(address(mockBlocklockReceiver) != address(0));
        assert(address(decryptionSender.signatureSchemeAddressProvider()) != address(0));
    }

    function test_FulfillBlocklockDirectFundingRequest() public {
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

        assert(!blocklockSender.s_configured());
        assert(!blocklockSender.s_disabled());

        // set blocklockSender contract config
        uint32 maxGasLimit = 500_000;
        uint32 gasAfterPaymentCalculation = 400_000;
        uint32 fulfillmentFlatFeeNativePPM = 1_000_000;
        uint8 nativePremiumPercentage = 10;

        setBlocklockSenderBillingConfiguration(
            maxGasLimit, gasAfterPaymentCalculation, fulfillmentFlatFeeNativePPM, nativePremiumPercentage
        );

        // get request price
        uint32 callbackGasLimit = 100_000;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);

        // fund blocklock receiver contract
        uint256 aliceBalance = alice.balance;

        vm.prank(alice);
        uint256 contractFundBuffer = 1 ether;
        mockBlocklockReceiver.fundContractNative{value: requestPrice + contractFundBuffer}();

        assertTrue(
            mockBlocklockReceiver.getBalance() == requestPrice + contractFundBuffer,
            "Incorrect ether balance for blocklock receiver contract"
        );
        assertTrue(alice.balance == aliceBalance - (requestPrice + contractFundBuffer), "Alice balance not debited");
        assertTrue(requestPrice > 0, "Invalid request price");

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = 100_000;
        (uint256 requestId,) = mockBlocklockReceiver.createTimelockRequestWithDirectFunding(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].chainHeight, ciphertextDataUint[3 ether].ciphertext
        );

        // fetch request information including callbackGasLimit from decryption sender
        TypesLib.DecryptionRequest memory decryptionRequest = decryptionSender.getRequest(requestId);

        /// @dev Overhead for EIP-150
        uint256 callbackGasOverhead = requestCallbackGasLimit / 63 + 1;

        assertTrue(
            decryptionRequest.callbackGasLimit > requestCallbackGasLimit,
            "Gas buffer for _getEIP150Overhead() not added to callbackGasLimit from user request"
        );
        assertTrue(
            decryptionRequest.callbackGasLimit
                == requestCallbackGasLimit + callbackGasOverhead + decryptionAndSignatureVerificationOverhead,
            "Incorrect Gas buffer for _getEIP150Overhead() added to callbackGasLimit from user request"
        );

        // fetch request information from blocklock sender
        TypesLib.BlocklockRequest memory blocklockRequest = blocklockSender.getRequest(requestId);

        assertTrue(blocklockRequest.subId == 0, "Direct funding request id should be zero");
        assertTrue(
            blocklockRequest.directFundingFeePaid > 0 && blocklockRequest.directFundingFeePaid == requestPrice,
            "Invalid price paid by user contract for request"
        );
        assertTrue(
            blocklockRequest.decryptionRequestID == requestId,
            "Request id mismatch between blocklockSender and decryptionSender"
        );

        // fulfill blocklock request
        /// @notice When we use less gas price, the total tx price including gas
        // limit for callback and external call from oracle is less than user payment or
        // calculated request price at request time
        // we don't use user payment as the gas price for callback from oracle.
        vm.txGasPrice(100_000);
        uint256 gasBefore = gasleft();

        vm.prank(admin);
        decryptionSender.fulfillDecryptionRequest(
            requestId, ciphertextDataUint[3 ether].decryptionKey, ciphertextDataUint[3 ether].signature
        );

        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;
        console.log("Request CallbackGasLimit:", decryptionRequest.callbackGasLimit);
        console.log("Request CallbackGasPrice:", blocklockRequest.directFundingFeePaid);
        console.log("Tx Gas used:", gasUsed);
        console.log("Tx Gas price (wei):", tx.gasprice);
        console.log("Tx Total cost (wei):", gasUsed * tx.gasprice);

        assertTrue(!decryptionSender.hasErrored(requestId), "Callback to receiver contract failed");

        decryptionRequest = decryptionSender.getRequest(requestId);
        assertTrue(decryptionRequest.isFulfilled, "Decryption key not provided in decryption sender by offchain oracle");
        assertTrue(
            mockBlocklockReceiver.plainTextValue() == ciphertextDataUint[3 ether].plaintext,
            "Plaintext values mismatch after decryption"
        );
        assertTrue(mockBlocklockReceiver.requestId() == 1, "Request id in receiver contract is incorrect");

        // check deductions from user and withdrawable amount in blocklock sender for admin
        blocklockRequest = blocklockSender.getRequest(requestId);

        console.log(blocklockRequest.directFundingFeePaid);
        assertTrue(
            blocklockSender.s_totalNativeBalance() == 0, "We don't expect any funded subscriptions at this point"
        );
        assertTrue(
            blocklockSender.s_withdrawableDirectFundingFeeNative() == blocklockRequest.directFundingFeePaid,
            "Request price paid should be withdrawable by admin at this point"
        );
        assertTrue(
            blocklockSender.s_withdrawableSubscriptionFeeNative() == 0,
            "We don't expect any funded subscriptions at this point"
        );

        vm.prank(admin);
        uint256 adminBalance = admin.balance;
        blocklockSender.withdrawDirectFundingFeesNative(payable(admin));
        assertTrue(
            admin.balance + blocklockRequest.directFundingFeePaid > adminBalance,
            "Admin balance should be higher after withdrawing fees"
        );
    }

    function test_NoChargeAtRequestTimeForBlocklockSubscriptionRequest() public {
        // set blocklockSender contract config
        uint32 maxGasLimit = 500_000;
        uint32 gasAfterPaymentCalculation = 400_000;
        uint32 fulfillmentFlatFeeNativePPM = 1_000_000;
        uint8 nativePremiumPercentage = 10;

        setBlocklockSenderBillingConfiguration(
            maxGasLimit, gasAfterPaymentCalculation, fulfillmentFlatFeeNativePPM, nativePremiumPercentage
        );

        // create subscription and fund it
        assert(mockBlocklockReceiver.subscriptionId() == 0);

        vm.prank(alice);
        mockBlocklockReceiver.createSubscriptionAndFundNative{value: 5 ether}();

        uint256 subId = mockBlocklockReceiver.subscriptionId();
        assert(subId != 0);
        console.log("Subscription id = ", subId);

        // top up subscription
        /// @notice Anyone can top up a subscription account
        vm.prank(admin);
        mockBlocklockReceiver.topUpSubscriptionNative{value: 1 ether}();

        uint256 expectedTotalSubBalance = 6 ether;

        // get subscription data
        (uint96 nativeBalance, uint64 reqCount, address subOwner, address[] memory consumers) =
            blocklockSender.getSubscription(subId);

        assert(nativeBalance == expectedTotalSubBalance);
        assert(reqCount == 0);
        assert(subOwner == address(mockBlocklockReceiver));
        assert(consumers.length == 1);
        assert(consumers[0] == address(mockBlocklockReceiver));

        assert(address(mockBlocklockReceiver).balance == 0);

        // get request price
        uint32 callbackGasLimit = 100_000;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);

        assertTrue(requestPrice > 0, "Invalid request price");

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = 100_000;
        uint256 requestId = mockBlocklockReceiver.createTimelockRequestWithSubscription(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].chainHeight, ciphertextDataUint[3 ether].ciphertext
        );

        // fetch request information including callbackGasLimit from decryption sender
        TypesLib.DecryptionRequest memory decryptionRequest = decryptionSender.getRequest(requestId);

        /// @dev Overhead for EIP-150
        uint256 callbackGasOverhead = requestCallbackGasLimit / 63 + 1;

        assertTrue(
            decryptionRequest.callbackGasLimit > requestCallbackGasLimit,
            "Gas buffer for _getEIP150Overhead() not added to callbackGasLimit from user request"
        );

        assertTrue(
            decryptionRequest.callbackGasLimit
                == requestCallbackGasLimit + callbackGasOverhead + decryptionAndSignatureVerificationOverhead,
            "Incorrect Gas buffer for _getEIP150Overhead() added to callbackGasLimit from user request"
        );

        // fetch request information from blocklock sender
        TypesLib.BlocklockRequest memory blocklockRequest = blocklockSender.getRequest(requestId);

        assertTrue(blocklockRequest.subId != 0, "Subscription funding request id should not be zero");
        assertTrue(
            blocklockRequest.directFundingFeePaid == 0,
            "User contract should not be charged immediately for subscription request"
        );
        assertTrue(
            blocklockRequest.decryptionRequestID == requestId,
            "Request id mismatch between blocklockSender and decryptionSender"
        );

        // subId not charged at this point, and request count for subId should not be increased
        (nativeBalance, reqCount,,) = blocklockSender.getSubscription(subId);

        assertTrue(nativeBalance == expectedTotalSubBalance, "subId should not be charged at this point");
        assertTrue(reqCount == 0, "Incorrect request count, it should be zero");
    }

    function test_FulfillBlocklockSubscriptionRequest() public {
        // set blocklockSender contract config
        uint32 maxGasLimit = 500_000;
        uint32 gasAfterPaymentCalculation = 400_000;
        uint32 fulfillmentFlatFeeNativePPM = 1_000_000;
        uint8 nativePremiumPercentage = 10;

        setBlocklockSenderBillingConfiguration(
            maxGasLimit, gasAfterPaymentCalculation, fulfillmentFlatFeeNativePPM, nativePremiumPercentage
        );

        // create subscription and fund it
        assert(mockBlocklockReceiver.subscriptionId() == 0);

        vm.prank(alice);
        mockBlocklockReceiver.createSubscriptionAndFundNative{value: 5 ether}();

        uint256 subId = mockBlocklockReceiver.subscriptionId();
        assert(subId != 0);
        console.log("Subscription id = ", subId);

        // top up subscription
        /// @notice Anyone can top up a subscription account
        vm.prank(admin);
        mockBlocklockReceiver.topUpSubscriptionNative{value: 1 ether}();

        uint256 totalSubBalanceBeforeRequest = 6 ether;

        // get request price
        uint32 callbackGasLimit = 100_000;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);
        console.log("Request price for offchain oracle callbackGasLimit", requestPrice);

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = 100_000;
        uint256 requestId = mockBlocklockReceiver.createTimelockRequestWithSubscription(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].chainHeight, ciphertextDataUint[3 ether].ciphertext
        );

        // fetch request information including callbackGasLimit from decryption sender
        TypesLib.DecryptionRequest memory decryptionRequest = decryptionSender.getRequest(requestId);

        /// @dev Overhead for EIP-150
        uint256 callbackGasOverhead = requestCallbackGasLimit / 63 + 1;

        assertTrue(
            decryptionRequest.callbackGasLimit > requestCallbackGasLimit,
            "Gas buffer for _getEIP150Overhead() not added to callbackGasLimit from user request"
        );

        assertTrue(
            decryptionRequest.callbackGasLimit
                == requestCallbackGasLimit + callbackGasOverhead + decryptionAndSignatureVerificationOverhead,
            "Incorrect Gas buffer for _getEIP150Overhead() added to callbackGasLimit from user request"
        );

        // fetch request information from blocklock sender
        TypesLib.BlocklockRequest memory blocklockRequest = blocklockSender.getRequest(requestId);

        assertTrue(blocklockRequest.subId != 0, "Subscription funding request id should not be zero");
        assertTrue(
            blocklockRequest.directFundingFeePaid == 0,
            "User contract should not be charged immediately for subscription request"
        );
        assertTrue(
            blocklockRequest.decryptionRequestID == requestId,
            "Request id mismatch between blocklockSender and decryptionSender"
        );

        // fulfill blocklock request
        /// @notice When we use less gas price, the total tx price including gas
        // limit for callback and external call from oracle is less than user payment or
        // calculated request price at request time
        // we don't use user payment as the gas price for callback from oracle.
        vm.txGasPrice(100_000);
        uint256 gasBefore = gasleft();

        vm.prank(admin);
        decryptionSender.fulfillDecryptionRequest(
            requestId, ciphertextDataUint[3 ether].decryptionKey, ciphertextDataUint[3 ether].signature
        );

        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;
        console.log("Request CallbackGasLimit:", decryptionRequest.callbackGasLimit);
        console.log("Request CallbackGasPrice:", blocklockRequest.directFundingFeePaid);
        console.log("Tx Gas used:", gasUsed);
        console.log("Tx Gas price (wei):", tx.gasprice);
        console.log("Tx Total cost (wei):", gasUsed * tx.gasprice);

        assertTrue(!decryptionSender.hasErrored(requestId), "Callback to receiver contract failed");

        // check for fee deductions from subscription account
        // subId should be charged at this point, and request count for subId should be increased
        (uint96 nativeBalance, uint256 reqCount,,) = blocklockSender.getSubscription(subId);

        console.log("Subscription native balance after request = ", nativeBalance);
        uint256 exactFeePaid = totalSubBalanceBeforeRequest - nativeBalance;
        console.log("Subscription account charge for request = ", exactFeePaid);
        assertTrue(totalSubBalanceBeforeRequest > nativeBalance, "subId should be charged at this point");
        // fixme compute exact cost for subscription type requests with formula
        assertTrue(gasUsed * tx.gasprice < exactFeePaid, "subId should be charged for overhead");
        assertTrue(reqCount == 1, "Incorrect request count, it should be one");

        decryptionRequest = decryptionSender.getRequest(requestId);
        assertTrue(decryptionRequest.isFulfilled, "Decryption key not provided in decryption sender by offchain oracle");
        assertTrue(
            mockBlocklockReceiver.plainTextValue() == ciphertextDataUint[3 ether].plaintext,
            "Plaintext values mismatch after decryption"
        );
        assertTrue(mockBlocklockReceiver.requestId() == 1, "Request id in receiver contract is incorrect");

        assertTrue(
            blocklockSender.s_withdrawableDirectFundingFeeNative() == 0,
            "We don't expect any direct funding payments from this subscription request"
        );
        /// @notice exactFeePaid is zero
        assertTrue(
            blocklockSender.s_withdrawableSubscriptionFeeNative() == exactFeePaid,
            "Request price paid should be withdrawable by admin at this point"
        );

        vm.prank(admin);
        uint256 adminBalance = admin.balance;
        blocklockSender.withdrawSubscriptionFeesNative(payable(admin));
        assertTrue(admin.balance + exactFeePaid > adminBalance, "Admin balance should be higher after withdrawing fees");

        assert(blocklockSender.s_totalNativeBalance() == nativeBalance);
    }

    function test_CancelSubscription() public {
        mockBlocklockReceiver = deployAndFundReceiverWithSubscription(alice, address(blocklockSender), 5 ether);

        uint256 aliceBalancePreCancellation = alice.balance;

        vm.prank(alice);
        mockBlocklockReceiver.cancelSubscription(alice);

        uint256 aliceBalancePostCancellation = alice.balance;

        assertTrue(
            aliceBalancePostCancellation > aliceBalancePreCancellation,
            "Balance did not increase after subscription cancellation"
        );
    }

    /// @notice enough gas overhead still added for requests with zero gas limit specified 
    /// to cover for sending of keys and decryption
    function test_FulfillBlocklockSubscriptionRequestWithZeroCallbackGasLimit() public {
        // set blocklockSender contract config
        uint32 maxGasLimit = 500_000;
        uint32 gasAfterPaymentCalculation = 400_000;
        uint32 fulfillmentFlatFeeNativePPM = 1_000_000;
        uint8 nativePremiumPercentage = 10;

        setBlocklockSenderBillingConfiguration(
            maxGasLimit, gasAfterPaymentCalculation, fulfillmentFlatFeeNativePPM, nativePremiumPercentage
        );

        // create subscription and fund it
        assert(mockBlocklockReceiver.subscriptionId() == 0);

        vm.prank(alice);
        mockBlocklockReceiver.createSubscriptionAndFundNative{value: 5 ether}();

        uint256 totalSubBalanceBeforeRequest = 5 ether;

        // get request price
        uint32 callbackGasLimit = 0;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);
        console.log("Request price for offchain oracle callbackGasLimit", requestPrice);

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = callbackGasLimit;
        uint256 requestId = mockBlocklockReceiver.createTimelockRequestWithSubscription(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].chainHeight, ciphertextDataUint[3 ether].ciphertext
        );

        // fetch request information including callbackGasLimit from decryption sender
        TypesLib.DecryptionRequest memory decryptionRequest = decryptionSender.getRequest(requestId);

        /// @dev Overhead for EIP-150
        uint256 callbackGasOverhead = requestCallbackGasLimit / 63 + 1;

        assertTrue(
            decryptionRequest.callbackGasLimit > requestCallbackGasLimit,
            "Gas buffer for _getEIP150Overhead() not added to callbackGasLimit from user request"
        );

        assertTrue(
            decryptionRequest.callbackGasLimit
                == requestCallbackGasLimit + callbackGasOverhead + decryptionAndSignatureVerificationOverhead,
            "Incorrect Gas buffer for _getEIP150Overhead() added to callbackGasLimit from user request"
        );

        // fetch request information from blocklock sender
        TypesLib.BlocklockRequest memory blocklockRequest = blocklockSender.getRequest(requestId);

        assertTrue(blocklockRequest.subId != 0, "Subscription funding request id should not be zero");
        assertTrue(
            blocklockRequest.directFundingFeePaid == 0,
            "User contract should not be charged immediately for subscription request"
        );
        assertTrue(
            blocklockRequest.decryptionRequestID == requestId,
            "Request id mismatch between blocklockSender and decryptionSender"
        );

        // fulfill blocklock request
        /// @notice When we use less gas price, the total tx price including gas
        // limit for callback and external call from oracle is less than user payment or
        // calculated request price at request time
        // we don't use user payment as the gas price for callback from oracle.
        vm.txGasPrice(100_000);
        uint256 gasBefore = gasleft();

        vm.prank(admin);
        decryptionSender.fulfillDecryptionRequest(
            requestId, ciphertextDataUint[3 ether].decryptionKey, ciphertextDataUint[3 ether].signature
        );

        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;
        console.log("Request CallbackGasLimit:", decryptionRequest.callbackGasLimit);
        console.log("Request CallbackGasPrice:", blocklockRequest.directFundingFeePaid);
        console.log("Tx Gas used:", gasUsed);
        console.log("Tx Gas price (wei):", tx.gasprice);
        console.log("Tx Total cost (wei):", gasUsed * tx.gasprice);

        assertTrue(!decryptionSender.hasErrored(requestId), "Callback to receiver contract failed");

        // check for fee deductions from subscription account
        // subId should be charged at this point, and request count for subId should be increased
        (uint96 nativeBalance, uint256 reqCount,,) = blocklockSender.getSubscription(blocklockRequest.subId);

        console.log("Subscription native balance after request = ", nativeBalance);
        uint256 exactFeePaid = totalSubBalanceBeforeRequest - nativeBalance;
        console.log("Subscription account charge for request = ", exactFeePaid);
        assertTrue(totalSubBalanceBeforeRequest > nativeBalance, "subId should be charged at this point");
        // fixme compute exact cost for subscription type requests with formula
        assertTrue(gasUsed * tx.gasprice < exactFeePaid, "subId should be charged for overhead");
        assertTrue(reqCount == 1, "Incorrect request count, it should be one");

        decryptionRequest = decryptionSender.getRequest(requestId);
        assertTrue(decryptionRequest.isFulfilled, "Decryption key not provided in decryption sender by offchain oracle");
        assertTrue(
            mockBlocklockReceiver.plainTextValue() == ciphertextDataUint[3 ether].plaintext,
            "Plaintext values mismatch after decryption"
        );
        assertTrue(mockBlocklockReceiver.requestId() == 1, "Request id in receiver contract is incorrect");

        assertTrue(
            blocklockSender.s_withdrawableDirectFundingFeeNative() == 0,
            "We don't expect any direct funding payments from this subscription request"
        );
        /// @notice exactFeePaid is zero
        assertTrue(
            blocklockSender.s_withdrawableSubscriptionFeeNative() == exactFeePaid,
            "Request price paid should be withdrawable by admin at this point"
        );

        vm.prank(admin);
        uint256 adminBalance = admin.balance;
        blocklockSender.withdrawSubscriptionFeesNative(payable(admin));
        assertTrue(admin.balance + exactFeePaid > adminBalance, "Admin balance should be higher after withdrawing fees");

        assert(blocklockSender.s_totalNativeBalance() == nativeBalance);
    }

    // fixme test cancelled subscription with a pending unfulfilled request leads to a failing callback without any decryption key stored onchain??
    function test_CancellingSubscriptionWithPendingRequestNotAllowed() public {
        // set blocklockSender contract config
        uint32 maxGasLimit = 500_000;
        uint32 gasAfterPaymentCalculation = 400_000;
        uint32 fulfillmentFlatFeeNativePPM = 1_000_000;
        uint8 nativePremiumPercentage = 10;

        setBlocklockSenderBillingConfiguration(
            maxGasLimit, gasAfterPaymentCalculation, fulfillmentFlatFeeNativePPM, nativePremiumPercentage
        );

        // create subscription and fund it
        assert(mockBlocklockReceiver.subscriptionId() == 0);

        vm.prank(alice);
        mockBlocklockReceiver.createSubscriptionAndFundNative{value: 5 ether}();

        uint256 totalSubBalanceBeforeRequest = 5 ether;

        // get request price
        uint32 callbackGasLimit = 0;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);
        console.log("Request price for offchain oracle callbackGasLimit", requestPrice);

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = callbackGasLimit;
        uint256 requestId = mockBlocklockReceiver.createTimelockRequestWithSubscription(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].chainHeight, ciphertextDataUint[3 ether].ciphertext
        );

        // fetch request information including callbackGasLimit from decryption sender
        TypesLib.DecryptionRequest memory decryptionRequest = decryptionSender.getRequest(requestId);

        /// @dev Overhead for EIP-150
        uint256 callbackGasOverhead = requestCallbackGasLimit / 63 + 1;

        assertTrue(
            decryptionRequest.callbackGasLimit > requestCallbackGasLimit,
            "Gas buffer for _getEIP150Overhead() not added to callbackGasLimit from user request"
        );

        assertTrue(
            decryptionRequest.callbackGasLimit
                == requestCallbackGasLimit + callbackGasOverhead + decryptionAndSignatureVerificationOverhead,
            "Incorrect Gas buffer for _getEIP150Overhead() added to callbackGasLimit from user request"
        );

        // fetch request information from blocklock sender
        TypesLib.BlocklockRequest memory blocklockRequest = blocklockSender.getRequest(requestId);

        assertTrue(blocklockRequest.subId != 0, "Subscription funding request id should not be zero");
        assertTrue(
            blocklockRequest.directFundingFeePaid == 0,
            "User contract should not be charged immediately for subscription request"
        );
        assertTrue(
            blocklockRequest.decryptionRequestID == requestId,
            "Request id mismatch between blocklockSender and decryptionSender"
        );

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSignature("PendingRequestExists()"));
        mockBlocklockReceiver.cancelSubscription(alice);

        assertTrue(blocklockSender.s_totalNativeBalance() == totalSubBalanceBeforeRequest, "User not charged");
    }
    
    function test_CallsToBlocklockSenderShouldRevertIfBlocklockSenderAddressIsIncorrect() public {
        // set blocklockSender contract config
        uint32 maxGasLimit = 500_000;
        uint32 gasAfterPaymentCalculation = 400_000;
        uint32 fulfillmentFlatFeeNativePPM = 1_000_000;
        uint8 nativePremiumPercentage = 10;

        setBlocklockSenderBillingConfiguration(
            maxGasLimit, gasAfterPaymentCalculation, fulfillmentFlatFeeNativePPM, nativePremiumPercentage
        );

        vm.prank(alice);
        mockBlocklockReceiver = new MockBlocklockReceiver(admin);

        vm.prank(alice);
        vm.expectRevert();
        mockBlocklockReceiver.createSubscriptionAndFundNative{value: 0}();
    }

    function test_RevertingCallbackForSubscriptionWithInsufficientBalanceAndRetry() public {
        // set blocklockSender contract config
        uint32 maxGasLimit = 500_000;
        uint32 gasAfterPaymentCalculation = 400_000;
        uint32 fulfillmentFlatFeeNativePPM = 1_000_000;
        uint8 nativePremiumPercentage = 10;

        setBlocklockSenderBillingConfiguration(
            maxGasLimit, gasAfterPaymentCalculation, fulfillmentFlatFeeNativePPM, nativePremiumPercentage
        );

        // create subscription but don't fund it
        assert(mockBlocklockReceiver.subscriptionId() == 0);

        vm.prank(alice);
        mockBlocklockReceiver.createSubscriptionAndFundNative{value: 0}();

        uint256 subId = mockBlocklockReceiver.subscriptionId();
        assert(subId != 0);
        console.log("Subscription id = ", subId);

        uint256 totalSubBalanceBeforeRequest = 0;

        // get request price
        uint32 callbackGasLimit = 100_000;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);
        console.log("Request price for offchain oracle callbackGasLimit", requestPrice);

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = 100_000;
        uint256 requestId = mockBlocklockReceiver.createTimelockRequestWithSubscription(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].chainHeight, ciphertextDataUint[3 ether].ciphertext
        );

        // fetch request information including callbackGasLimit from decryption sender
        TypesLib.DecryptionRequest memory decryptionRequest = decryptionSender.getRequest(requestId);

        /// @dev Overhead for EIP-150
        uint256 callbackGasOverhead = requestCallbackGasLimit / 63 + 1;

        assertTrue(
            decryptionRequest.callbackGasLimit > requestCallbackGasLimit,
            "Gas buffer for _getEIP150Overhead() not added to callbackGasLimit from user request"
        );

        assertTrue(
            decryptionRequest.callbackGasLimit
                == requestCallbackGasLimit + callbackGasOverhead + decryptionAndSignatureVerificationOverhead,
            "Incorrect Gas buffer for _getEIP150Overhead() added to callbackGasLimit from user request"
        );

        // fetch request information from blocklock sender
        TypesLib.BlocklockRequest memory blocklockRequest = blocklockSender.getRequest(requestId);

        assertTrue(blocklockRequest.subId != 0, "Subscription funding request id should not be zero");
        assertTrue(
            blocklockRequest.directFundingFeePaid == 0,
            "User contract should not be charged immediately for subscription request"
        );
        assertTrue(
            blocklockRequest.decryptionRequestID == requestId,
            "Request id mismatch between blocklockSender and decryptionSender"
        );

        // fulfill blocklock request
        /// @notice When we use less gas price, the total tx price including gas
        // limit for callback and external call from oracle is less than user payment or
        // calculated request price at request time
        // we don't use user payment as the gas price for callback from oracle.
        vm.txGasPrice(100_000);
        uint256 gasBefore = gasleft();

        vm.prank(admin);
        decryptionSender.fulfillDecryptionRequest(requestId, ciphertextDataUint[3 ether].decryptionKey, ciphertextDataUint[3 ether].signature);

        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;
        console.log("Request CallbackGasLimit:", decryptionRequest.callbackGasLimit);
        console.log("Request CallbackGasPrice:", blocklockRequest.directFundingFeePaid);
        console.log("Tx Gas used:", gasUsed);
        console.log("Tx Gas price (wei):", tx.gasprice);
        console.log("Tx Total cost (wei):", gasUsed * tx.gasprice);

        /// @notice reverting callback should add request id to the erroredRequestIds set in decryptionSender
        assertTrue(decryptionSender.hasErrored(requestId), "Callback to receiver contract failed");

        // check for fee deductions from subscription account
        // subId should be charged at this point, and request count for subId should be increased
        (uint96 nativeBalance, uint256 reqCount,,) = blocklockSender.getSubscription(subId);

        console.log("Subscription native balance after request = ", nativeBalance);
        uint256 exactFeePaid = totalSubBalanceBeforeRequest - nativeBalance;
        console.log("Subscription account charge for request = ", exactFeePaid);
        assertTrue(
            totalSubBalanceBeforeRequest == nativeBalance + exactFeePaid, "subId should NOT be charged at this point"
        );
        assert(exactFeePaid == 0);
        assertTrue(reqCount == 0, "Incorrect request count, it should be zero");

        decryptionRequest = decryptionSender.getRequest(requestId);
        assertTrue(decryptionRequest.isFulfilled, "Decryption key not provided in decryption sender by offchain oracle");
        assertTrue(
            mockBlocklockReceiver.plainTextValue() != ciphertextDataUint[3 ether].plaintext,
            "Ciphertext should not be decrypted yet"
        );
        assertTrue(mockBlocklockReceiver.requestId() == 1, "Request id in receiver contract is incorrect");

        assertTrue(
            blocklockSender.s_withdrawableDirectFundingFeeNative() == 0,
            "We don't expect any direct funding payments from this subscription request"
        );
        assertTrue(
            blocklockSender.s_withdrawableSubscriptionFeeNative() == exactFeePaid,
            "Request price paid should be withdrawable by admin at this point"
        );

        vm.prank(admin);
        uint256 adminBalance = admin.balance;
        vm.expectRevert(abi.encodeWithSignature("InsufficientBalance()"));
        blocklockSender.withdrawSubscriptionFeesNative(payable(admin));
        assertTrue(
            admin.balance + exactFeePaid == adminBalance, "Admin balance should remain the same if exactFeePaid is zero"
        );

        assert(blocklockSender.s_totalNativeBalance() == nativeBalance);

        // top up subscription
        /// @notice Anyone can top up a subscription account
        vm.prank(admin);
        mockBlocklockReceiver.topUpSubscriptionNative{value: 2 ether}();

        decryptionRequest = decryptionSender.getRequest(requestId);
        /// @notice retry tx needs higher gas limit
        uint32 newCallbackGasLimit = callbackGasLimit * 4;

        vm.txGasPrice(100_000);
        gasBefore = gasleft();

        vm.prank(admin);
        decryptionSender.retryCallbackWithSubscription(requestId, newCallbackGasLimit);

        gasAfter = gasleft();
        gasUsed = gasBefore - gasAfter;
        console.log("Request CallbackGasLimit:", newCallbackGasLimit);
        console.log("Request CallbackGasPrice:", blocklockRequest.directFundingFeePaid);
        console.log("Retry Tx Gas used:", gasUsed);
        console.log("Retry Tx Gas price (wei):", tx.gasprice);
        console.log("Retry Tx Total cost (wei):", gasUsed * tx.gasprice);

        assertTrue(
            mockBlocklockReceiver.plainTextValue() == ciphertextDataUint[3 ether].plaintext,
            "Plaintext should be decrypted after callback retry"
        );

        assertTrue(!decryptionSender.hasErrored(requestId), "Callback to receiver contract should have passed");

        vm.prank(admin);
        uint256 adminBalancePreWithdrawal = admin.balance;
        blocklockSender.withdrawSubscriptionFeesNative(payable(admin));
        assertTrue(adminBalancePreWithdrawal < admin.balance, "Admin balance should be higher after withdrawing fees");
    }

    function test_RevertingCallbackForSubscriptionWithIncorrectDecryptionKey() public {
        // set blocklockSender contract config
        uint32 maxGasLimit = 500_000;
        uint32 gasAfterPaymentCalculation = 400_000;
        uint32 fulfillmentFlatFeeNativePPM = 1_000_000;
        uint8 nativePremiumPercentage = 10;

        setBlocklockSenderBillingConfiguration(
            maxGasLimit, gasAfterPaymentCalculation, fulfillmentFlatFeeNativePPM, nativePremiumPercentage
        );

        // create subscription and fund it
        assert(mockBlocklockReceiver.subscriptionId() == 0);

        vm.prank(alice);
        mockBlocklockReceiver.createSubscriptionAndFundNative{value: 5 ether}();

        uint256 subId = mockBlocklockReceiver.subscriptionId();
        assert(subId != 0);
        console.log("Subscription id = ", subId);

        // top up subscription
        /// @notice Anyone can top up a subscription account
        vm.prank(admin);
        mockBlocklockReceiver.topUpSubscriptionNative{value: 1 ether}();

        uint256 totalSubBalanceBeforeRequest = 6 ether;

        // get request price
        uint32 callbackGasLimit = 100_000;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);
        console.log("Request price for offchain oracle callbackGasLimit", requestPrice);

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = 100_000;
        uint256 requestId = mockBlocklockReceiver.createTimelockRequestWithSubscription(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].chainHeight, ciphertextDataUint[3 ether].ciphertext
        );

        // fetch request information including callbackGasLimit from decryption sender
        TypesLib.DecryptionRequest memory decryptionRequest = decryptionSender.getRequest(requestId);

        /// @dev Overhead for EIP-150
        uint256 callbackGasOverhead = requestCallbackGasLimit / 63 + 1;

        assertTrue(
            decryptionRequest.callbackGasLimit > requestCallbackGasLimit,
            "Gas buffer for _getEIP150Overhead() not added to callbackGasLimit from user request"
        );

        assertTrue(
            decryptionRequest.callbackGasLimit
                == requestCallbackGasLimit + callbackGasOverhead + decryptionAndSignatureVerificationOverhead,
            "Incorrect Gas buffer for _getEIP150Overhead() added to callbackGasLimit from user request"
        );

        // fetch request information from blocklock sender
        TypesLib.BlocklockRequest memory blocklockRequest = blocklockSender.getRequest(requestId);

        assertTrue(blocklockRequest.subId != 0, "Subscription funding request id should not be zero");
        assertTrue(
            blocklockRequest.directFundingFeePaid == 0,
            "User contract should not be charged immediately for subscription request"
        );
        assertTrue(
            blocklockRequest.decryptionRequestID == requestId,
            "Request id mismatch between blocklockSender and decryptionSender"
        );

        // fulfill blocklock request
        /// @notice When we use less gas price, the total tx price including gas
        // limit for callback and external call from oracle is less than user payment or
        // calculated request price at request time
        // we don't use user payment as the gas price for callback from oracle.
        vm.txGasPrice(100_000);
        uint256 gasBefore = gasleft();

        vm.prank(admin);
        decryptionSender.fulfillDecryptionRequest(requestId, hex"00", ciphertextDataUint[3 ether].signature);

        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;
        console.log("Request CallbackGasLimit:", decryptionRequest.callbackGasLimit);
        console.log("Request CallbackGasPrice:", blocklockRequest.directFundingFeePaid);
        console.log("Tx Gas used:", gasUsed);
        console.log("Tx Gas price (wei):", tx.gasprice);
        console.log("Tx Total cost (wei):", gasUsed * tx.gasprice);

        /// @notice reverting callback should add request id to the erroredRequestIds set in decryptionSender
        assertTrue(decryptionSender.hasErrored(requestId), "Callback to receiver contract failed");

        // check for fee deductions from subscription account
        // subId should be charged at this point, and request count for subId should be increased
        (uint96 nativeBalance, uint256 reqCount,,) = blocklockSender.getSubscription(subId);

        console.log("Subscription native balance after request = ", nativeBalance);
        uint256 exactFeePaid = totalSubBalanceBeforeRequest - nativeBalance;
        console.log("Subscription account charge for request = ", exactFeePaid);
        assertTrue(
            totalSubBalanceBeforeRequest == nativeBalance + exactFeePaid, "subId should NOT be charged at this point"
        );
        assert(exactFeePaid == 0);
        assertTrue(reqCount == 0, "Incorrect request count, it should be zero");

        decryptionRequest = decryptionSender.getRequest(requestId);
        assertTrue(decryptionRequest.isFulfilled, "Decryption key not provided in decryption sender by offchain oracle");
        assertTrue(
            mockBlocklockReceiver.plainTextValue() != ciphertextDataUint[3 ether].plaintext,
            "Ciphertext should not be decrypted yet"
        );
        assertTrue(mockBlocklockReceiver.requestId() == 1, "Request id in receiver contract is incorrect");

        assertTrue(
            blocklockSender.s_withdrawableDirectFundingFeeNative() == 0,
            "We don't expect any direct funding payments from this subscription request"
        );
        assertTrue(
            blocklockSender.s_withdrawableSubscriptionFeeNative() == exactFeePaid,
            "Request price paid should be withdrawable by admin at this point"
        );

        vm.prank(admin);
        uint256 adminBalance = admin.balance;
        vm.expectRevert(abi.encodeWithSignature("InsufficientBalance()"));
        blocklockSender.withdrawSubscriptionFeesNative(payable(admin));
        assertTrue(
            admin.balance + exactFeePaid == adminBalance, "Admin balance should remain the same if exactFeePaid is zero"
        );

        assert(blocklockSender.s_totalNativeBalance() == nativeBalance);
    }

    function test_UnauthorisedCallerReverts() public {
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

        // set blocklockSender contract config
        uint32 maxGasLimit = 500_000;
        uint32 gasAfterPaymentCalculation = 400_000;
        uint32 fulfillmentFlatFeeNativePPM = 1_000_000;
        uint8 nativePremiumPercentage = 10;

        setBlocklockSenderBillingConfiguration(
            maxGasLimit, gasAfterPaymentCalculation, fulfillmentFlatFeeNativePPM, nativePremiumPercentage
        );

        // get request price
        uint32 callbackGasLimit = 100_000;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);

        // fund blocklock receiver contract
        uint256 aliceBalance = alice.balance;

        vm.prank(alice);
        uint256 contractFundBuffer = 1 ether;
        mockBlocklockReceiver.fundContractNative{value: requestPrice + contractFundBuffer}();

        assertTrue(
            mockBlocklockReceiver.getBalance() == requestPrice + contractFundBuffer,
            "Incorrect ether balance for blocklock receiver contract"
        );
        assertTrue(alice.balance == aliceBalance - (requestPrice + contractFundBuffer), "Alice balance not debited");
        assertTrue(requestPrice > 0, "Invalid request price");

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = 100_000;
        (uint256 requestId,) = mockBlocklockReceiver.createTimelockRequestWithDirectFunding(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].chainHeight, ciphertextDataUint[3 ether].ciphertext
        );

        vm.prank(admin);
        vm.expectRevert();
        mockBlocklockReceiver.receiveBlocklock(requestId, ciphertextDataUint[3 ether].decryptionKey);

        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 1);
    }

    function test_InvalidRequestIdForDirectFundingRequestReverts() public {
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

        // set blocklockSender contract config
        uint32 maxGasLimit = 500_000;
        uint32 gasAfterPaymentCalculation = 400_000;
        uint32 fulfillmentFlatFeeNativePPM = 1_000_000;
        uint8 nativePremiumPercentage = 10;

        setBlocklockSenderBillingConfiguration(
            maxGasLimit, gasAfterPaymentCalculation, fulfillmentFlatFeeNativePPM, nativePremiumPercentage
        );

        // get request price
        uint32 callbackGasLimit = 100_000;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);

        // fund blocklock receiver contract
        uint256 aliceBalance = alice.balance;

        vm.prank(alice);
        uint256 contractFundBuffer = 1 ether;
        mockBlocklockReceiver.fundContractNative{value: requestPrice + contractFundBuffer}();

        assertTrue(
            mockBlocklockReceiver.getBalance() == requestPrice + contractFundBuffer,
            "Incorrect ether balance for blocklock receiver contract"
        );
        assertTrue(alice.balance == aliceBalance - (requestPrice + contractFundBuffer), "Alice balance not debited");
        assertTrue(requestPrice > 0, "Invalid request price");

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = 100_000;
        (uint256 requestId,) = mockBlocklockReceiver.createTimelockRequestWithDirectFunding(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].chainHeight, ciphertextDataUint[3 ether].ciphertext
        );

        vm.expectRevert("No request with specified requestID");
        vm.prank(admin);
        decryptionSender.fulfillDecryptionRequest(
            requestId + 1, ciphertextDataUint[3 ether].decryptionKey, ciphertextDataUint[3 ether].signature
        );

        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 1);
    }

    function test_InvalidSignatureForDirectFundingRequestReverts() public {
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

        // set blocklockSender contract config
        uint32 maxGasLimit = 500_000;
        uint32 gasAfterPaymentCalculation = 400_000;
        uint32 fulfillmentFlatFeeNativePPM = 1_000_000;
        uint8 nativePremiumPercentage = 10;
        setBlocklockSenderBillingConfiguration(
            maxGasLimit, gasAfterPaymentCalculation, fulfillmentFlatFeeNativePPM, nativePremiumPercentage
        );

        // get request price
        uint32 callbackGasLimit = 100_000;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);

        // fund blocklock receiver contract
        uint256 aliceBalance = alice.balance;

        vm.prank(alice);
        uint256 contractFundBuffer = 1 ether;
        mockBlocklockReceiver.fundContractNative{value: requestPrice + contractFundBuffer}();

        assertTrue(
            mockBlocklockReceiver.getBalance() == requestPrice + contractFundBuffer,
            "Incorrect ether balance for blocklock receiver contract"
        );
        assertTrue(alice.balance == aliceBalance - (requestPrice + contractFundBuffer), "Alice balance not debited");
        assertTrue(requestPrice > 0, "Invalid request price");

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = 100_000;
        (uint256 requestId,) = mockBlocklockReceiver.createTimelockRequestWithDirectFunding(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].chainHeight, ciphertextDataUint[3 ether].ciphertext
        );

        vm.prank(admin);
        bytes memory invalidSignature =
            hex"02a3b2fa2c402d59e22a2f141e32a092603862a06a695cbfb574c440372a72cd0636ba8092f304e7701ae9abe910cb474edf0408d9dd78ea7f6f97b7f2464711";
        vm.expectRevert("Signature verification failed");
        decryptionSender.fulfillDecryptionRequest(
            requestId, ciphertextDataUint[3 ether].decryptionKey, invalidSignature
        );

        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 1);
    }

    // helper functions
    function setBlocklockSenderBillingConfiguration(
        uint32 maxGasLimit,
        uint32 gasAfterPaymentCalculation,
        uint32 fulfillmentFlatFeeNativePPM,
        uint8 nativePremiumPercentage
    ) internal {
        vm.prank(admin);
        blocklockSender.setConfig(
            maxGasLimit, gasAfterPaymentCalculation, fulfillmentFlatFeeNativePPM, nativePremiumPercentage
        );
    }
}
