// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {console} from "forge-std/Test.sol";

import {
    Deployment,
    SignatureSchemeAddressProvider,
    BlocklockSender,
    BlocklockSignatureScheme,
    DecryptionSender,
    MockBlocklockReceiver,
    MockBlocklockRevertingReceiver,
    BlocklockTest,
    TypesLib,
    BLS
} from "./base/Blocklock.t.sol";

/// @title SubscriptionFundingTest test contract
/// @notice Tests for requests paid for via the subscription funding route
contract SubscriptionFundingTest is BlocklockTest {
    address[] public consumersToAddToSubscription;

    function test_noChargeAtRequestTime_forBlocklockSubscriptionRequest() public {
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
                == requestCallbackGasLimit + callbackGasOverhead + callbackWithDecryptionAndSignatureVerificationOverhead,
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

    function test_fulfillBlocklock_SubscriptionRequest() public {
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
                == requestCallbackGasLimit + callbackGasOverhead + callbackWithDecryptionAndSignatureVerificationOverhead,
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

        assertTrue(!decryptionSender.hasErrored(requestId), "Callback to receiver contract should not fail");

        // check for fee deductions from subscription account
        // subId should be charged at this point, and request count for subId should be increased
        (uint96 nativeBalance, uint256 reqCount,,) = blocklockSender.getSubscription(subId);

        uint256 exactFeePaid = totalSubBalanceBeforeRequest - nativeBalance;

        console.log("Subscription native balance after request = ", nativeBalance);
        console.log("Subscription fee charged for request = ", exactFeePaid);
        /// @notice check that the exactFeePaid is covered by estimated price and not higher than estimated price derived from
        /// calling blocklockSender.calculateRequestPriceNative(callbackGasLimit);
        console.log(totalSubBalanceBeforeRequest, nativeBalance, exactFeePaid);
        assertTrue(requestPrice >= exactFeePaid, "Request price estimation should cover exact fee charged for request");
        assertTrue(
            totalSubBalanceBeforeRequest == exactFeePaid + nativeBalance, "subId should be charged at this point"
        );

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

    function test_fulfillBlocklock_SubscriptionRequest_withRevertingReceiver() public {
        /// @dev test we can still collect payment for reverting callback receiver and
        /// payment is not blocked for subscription funding (and direct funding in direct funding test)

        // create subscription and fund it
        assert(mockBlocklockReceiver.subscriptionId() == 0);

        vm.prank(alice);
        MockBlocklockRevertingReceiver mockBlocklockReceiver =
            new MockBlocklockRevertingReceiver(address(blocklockSender));

        vm.prank(alice);
        mockBlocklockReceiver.createSubscriptionAndFundNative{value: 5 ether}();

        uint256 subId = mockBlocklockReceiver.subscriptionId();
        assert(subId != 0);
        console.log("Subscription id = ", subId);

        uint256 totalSubBalanceBeforeRequest = 5 ether;

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
                == requestCallbackGasLimit + callbackGasOverhead + callbackWithDecryptionAndSignatureVerificationOverhead,
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
        vm.expectEmit(true, true, false, true);
        emit BlocklockSender.BlocklockCallbackFailed(requestId);
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

        assertTrue(
            !decryptionSender.hasErrored(requestId),
            "Callback to receiver contract should not fail due to lack of funds"
        );

        // check for fee deductions from subscription account
        // subId should be charged at this point, and request count for subId should be increased
        (uint96 nativeBalance, uint256 reqCount,,) = blocklockSender.getSubscription(subId);

        uint256 exactFeePaid = totalSubBalanceBeforeRequest - nativeBalance;

        console.log("Subscription native balance after request = ", nativeBalance);
        console.log("Subscription fee charged for request = ", exactFeePaid);
        /// @notice check that the exactFeePaid is covered by estimated price and not higher than estimated price derived from
        /// calling blocklockSender.calculateRequestPriceNative(callbackGasLimit);
        console.log(totalSubBalanceBeforeRequest, nativeBalance, exactFeePaid);
        assertTrue(requestPrice >= exactFeePaid, "Request price estimation should cover exact fee charged for request");
        assertTrue(
            totalSubBalanceBeforeRequest == exactFeePaid + nativeBalance, "subId should be charged at this point"
        );

        assertTrue(gasUsed * tx.gasprice < exactFeePaid, "subId should be charged for overhead");
        assertTrue(reqCount == 1, "Incorrect request count, it should be one");

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

    function test_fulfillBlocklockRequest_forAdditionalSubscriberAddress() public {
        // create subscription and fund it
        vm.prank(alice);
        mockBlocklockReceiver.createSubscriptionAndFundNative{value: 5 ether}();

        uint256 subId = mockBlocklockReceiver.subscriptionId();
        uint256 totalSubBalanceBeforeRequest = 5 ether;

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

        // fulfill blocklock request
        /// @notice When we use less gas price, the total tx price including gas
        // limit for callback and external call from oracle is less than user payment or
        // calculated request price at request time
        // we don't use user payment as the gas price for callback from oracle.
        vm.txGasPrice(100_000);
        vm.prank(admin);
        uint256 gasBefore = gasleft();
        decryptionSender.fulfillDecryptionRequest(
            requestId, ciphertextDataUint[3 ether].decryptionKey, ciphertextDataUint[3 ether].signature
        );
        uint256 gasAfterFirstRequest = gasBefore - gasleft();

        // deploy new blocklock receiver with bob as owner
        vm.prank(bob);
        MockBlocklockReceiver secondBlocklockReceiver = new MockBlocklockReceiver(address(blocklockSender));

        // update subscription via initial blocklockReceiver contract
        consumersToAddToSubscription.push(address(secondBlocklockReceiver));

        vm.prank(alice);
        mockBlocklockReceiver.updateSubscription(consumersToAddToSubscription);

        // set subscription id in newly added consumer contract
        vm.prank(bob);
        secondBlocklockReceiver.setSubId(subId);

        // make second blocklock request from newly added consumer contract
        vm.prank(bob);
        uint256 second_requestId = secondBlocklockReceiver.createTimelockRequestWithSubscription(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].chainHeight, ciphertextDataUint[3 ether].ciphertext
        );

        // fulfill second blocklock request
        /// @notice When we use less gas price, the total tx price including gas
        // limit for callback and external call from oracle is less than user payment or
        // calculated request price at request time
        // we don't use user payment as the gas price for callback from oracle.
        vm.txGasPrice(100_000);
        vm.prank(admin);
        vm.expectRevert("No pending request with specified requestID");
        decryptionSender.fulfillDecryptionRequest(
            requestId, ciphertextDataUint[3 ether].decryptionKey, ciphertextDataUint[3 ether].signature
        );

        vm.txGasPrice(100_000);
        vm.prank(admin);
        vm.expectEmit(true, true, false, true);
        emit BlocklockSender.BlocklockCallbackSuccess(
            second_requestId,
            ciphertextDataUint[3 ether].chainHeight,
            ciphertextDataUint[3 ether].ciphertext,
            ciphertextDataUint[3 ether].decryptionKey
        );
        gasBefore = gasleft();
        decryptionSender.fulfillDecryptionRequest(
            second_requestId, ciphertextDataUint[3 ether].decryptionKey, ciphertextDataUint[3 ether].signature
        );
        uint256 gasAfterSecondRequest = gasBefore - gasleft();

        // check for fee deductions from subscription account
        // subId should be charged at this point, and request count for subId should be increased
        (uint96 nativeBalance, uint256 reqCount,,) = blocklockSender.getSubscription(subId);

        uint256 exactFeePaid = totalSubBalanceBeforeRequest - nativeBalance;

        console.log("Subscription native balance after both requests = ", nativeBalance);
        console.log("Subscription fee charged for both requests = ", exactFeePaid);
        console.log("Subscription fee native balance before for both requests = ", totalSubBalanceBeforeRequest);
        console.log("Exact gas cost for both fulfill tx", (gasAfterSecondRequest + gasAfterFirstRequest) * 100_000);

        /// @notice check that the exactFeePaid is covered by estimated price and not higher than estimated price derived from
        /// calling blocklockSender.calculateRequestPriceNative(callbackGasLimit);
        assertTrue(
            requestPrice * 2 >= exactFeePaid, "Request price estimation should cover exact fee charged for request"
        );
        assertTrue(
            totalSubBalanceBeforeRequest == exactFeePaid + nativeBalance, "subId should be charged at this point"
        );

        assertTrue(reqCount == 2, "Incorrect request count, it should be two for both consumers");

        TypesLib.DecryptionRequest memory decryptionRequest = decryptionSender.getRequest(second_requestId);
        assertTrue(decryptionRequest.isFulfilled, "Decryption key not provided in decryption sender by offchain oracle");
        assertTrue(
            secondBlocklockReceiver.plainTextValue() == ciphertextDataUint[3 ether].plaintext,
            "Plaintext values mismatch after decryption"
        );
        assertTrue(
            mockBlocklockReceiver.requestId() == 1 && secondBlocklockReceiver.requestId() == 2,
            "Request id in receiver contract is incorrect"
        );

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

    function test_fulfillBlocklock_SubscriptionRequest_withOnlyRequestPriceBalance() public {
        // get request price
        uint32 callbackGasLimit = 100_000;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);
        console.log("Request price for offchain oracle callbackGasLimit", requestPrice);

        // create subscription and fund it
        assert(mockBlocklockReceiver.subscriptionId() == 0);

        vm.prank(alice);
        mockBlocklockReceiver.createSubscriptionAndFundNative{value: requestPrice}();

        uint256 subId = mockBlocklockReceiver.subscriptionId();
        assert(subId != 0);
        console.log("Subscription id = ", subId);

        uint256 totalSubBalanceBeforeRequest = requestPrice;

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
                == requestCallbackGasLimit + callbackGasOverhead + callbackWithDecryptionAndSignatureVerificationOverhead,
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

        assertTrue(
            !decryptionSender.hasErrored(requestId),
            "Callback to receiver contract should not fail due to lack of funds"
        );

        // check for fee deductions from subscription account
        // subId should be charged at this point, and request count for subId should be increased
        (uint96 nativeBalance, uint256 reqCount,,) = blocklockSender.getSubscription(subId);

        uint256 exactFeePaid = totalSubBalanceBeforeRequest - nativeBalance;

        console.log("Subscription native balance after request = ", nativeBalance);
        console.log("Subscription fee charged for request = ", exactFeePaid);
        /// @notice check that the estimated price covers the exactFeePaid to ensure that
        /// exactFeePaid is not higher than estimated price derived from
        /// calling blocklockSender.calculateRequestPriceNative(callbackGasLimit);
        console.log(totalSubBalanceBeforeRequest, nativeBalance, exactFeePaid);
        assertTrue(requestPrice >= exactFeePaid, "Request price estimation should cover exact fee charged for request");
        assertTrue(
            totalSubBalanceBeforeRequest == exactFeePaid + nativeBalance, "subId should be charged at this point"
        );

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

    function test_cancelSubscription() public {
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
    function test_fulfillBlocklock_SubscriptionRequest_withZeroCallbackGasLimit() public {
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
                == requestCallbackGasLimit + callbackGasOverhead + callbackWithDecryptionAndSignatureVerificationOverhead,
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

        assertTrue(
            !decryptionSender.hasErrored(requestId),
            "Callback to receiver contract should not fail due to lack of funds"
        );

        // check for fee deductions from subscription account
        // subId should be charged at this point, and request count for subId should be increased
        (uint96 nativeBalance, uint256 reqCount,,) = blocklockSender.getSubscription(blocklockRequest.subId);

        console.log("Subscription native balance after request = ", nativeBalance);
        uint256 exactFeePaid = totalSubBalanceBeforeRequest - nativeBalance;
        console.log("Subscription fee charged for request = ", exactFeePaid);
        assertTrue(totalSubBalanceBeforeRequest > nativeBalance, "subId should be charged at this point");
        // check exact gas cost for the whole transaction
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

    function test_cancellingSubscription_withPendingRequest_notAllowed() public {
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
                == requestCallbackGasLimit + callbackGasOverhead + callbackWithDecryptionAndSignatureVerificationOverhead,
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

    function test_callback_forSubscriptionWithZeroBalance_reverts() public {
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
                == requestCallbackGasLimit + callbackGasOverhead + callbackWithDecryptionAndSignatureVerificationOverhead,
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

        /// @notice reverting callback should add request id to the erroredRequestIds set in decryptionSender
        /// @dev reverts due to fee collection failing, not callback / receiver contract logic
        /// @dev even though we only emit event for failing calls to receiver contracts,
        /// we can still catch failing fee collections
        assertTrue(decryptionSender.hasErrored(requestId), "Callback to receiver contract should have failed");

        // check for fee deductions from subscription account
        // subId should not be charged at this point, and request count for subId should be increased
        (uint96 nativeBalance, uint256 reqCount,,) = blocklockSender.getSubscription(subId);

        console.log("Subscription native balance after request = ", nativeBalance);
        uint256 exactFeePaid = totalSubBalanceBeforeRequest - nativeBalance;
        console.log("Subscription fee charged for request = ", exactFeePaid);
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

    function test_callback_forSubscriptionWithIncorrectDecryptionKey_reverts() public {
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
        uint32 callbackGasLimit = 50_000;
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
                == requestCallbackGasLimit + callbackGasOverhead + callbackWithDecryptionAndSignatureVerificationOverhead,
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
        vm.txGasPrice(400_000);
        uint256 gasBefore = gasleft();

        vm.prank(admin);
        // @dev for callback issues from the oracle, we don't expect a callback failed event
        // or charge to user. We detect them before doing the callback, e.g., failing signature
        // verification or decryption verification, so we ignore BlocklockCallbackFailed event check here.
        // vm.expectEmit();
        // emit BlocklockSender.BlocklockCallbackFailed(requestId);
        vm.expectRevert("Decryption verification failed");
        decryptionSender.fulfillDecryptionRequest(requestId, hex"00", ciphertextDataUint[3 ether].signature);

        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;
        console.log("Request CallbackGasLimit:", decryptionRequest.callbackGasLimit);
        console.log("Request CallbackGasPrice:", blocklockRequest.directFundingFeePaid);
        console.log("Tx Gas used:", gasUsed);
        console.log("Tx Gas price (wei):", tx.gasprice);
        console.log("Tx Total cost (wei):", gasUsed * tx.gasprice);

        /// @notice reverting callback should add request id to the erroredRequestIds set in decryptionSender
        /// @dev for failing callbacks, the request id is not added to list of errored callbacks
        assertTrue(
            !decryptionSender.hasErrored(requestId), "Callback to receiver contract should not have been executed"
        );

        // check for fee deductions from subscription account
        // subId should be charged at this point, and request count for subId should be increased
        (uint96 nativeBalance, uint256 reqCount,,) = blocklockSender.getSubscription(subId);
        uint256 exactFeePaid = totalSubBalanceBeforeRequest - nativeBalance;

        console.log("Subscription native balance after request = ", nativeBalance);
        console.log("Subscription fee charged for request = ", exactFeePaid);

        console.log(totalSubBalanceBeforeRequest, nativeBalance, exactFeePaid);

        assertTrue(exactFeePaid == 0, "Exact fee paid should be zero");
        assertTrue(
            totalSubBalanceBeforeRequest == exactFeePaid + nativeBalance, "subId should not be charged at this point"
        );
        // check fee paid covers tx gas price and overhead
        assertTrue(gasUsed * tx.gasprice > exactFeePaid, "Actual gas price should be less than exact fee paid");
        assertTrue(reqCount == 0, "Incorrect request count, it should be one");

        decryptionRequest = decryptionSender.getRequest(requestId);
        assertTrue(!decryptionRequest.isFulfilled, "Decryption key was incorrect so request not fulfilled");
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
        vm.expectRevert(abi.encodeWithSignature("InsufficientBalance()"));
        uint256 adminBalance = admin.balance;
        blocklockSender.withdrawSubscriptionFeesNative(payable(admin));
        assertTrue(admin.balance == adminBalance, "Admin balance should not increase after zero fee collection");

        assert(blocklockSender.s_totalNativeBalance() == nativeBalance);

        /// @notice we can retry fulfilling the request with the correct decryption key
        /// fulfill blocklock request
        /// @notice When we use less gas price, the total tx price including gas
        /// limit for callback and external call from oracle is less than user payment or
        /// calculated request price at request time
        /// we don't use user payment as the gas price for callback from oracle.
        vm.txGasPrice(100_000);
        gasBefore = gasleft();

        vm.prank(admin);
        decryptionSender.fulfillDecryptionRequest(
            requestId, ciphertextDataUint[3 ether].decryptionKey, ciphertextDataUint[3 ether].signature
        );

        gasAfter = gasleft();
        gasUsed = gasBefore - gasAfter;
        console.log("Request CallbackGasLimit:", decryptionRequest.callbackGasLimit);
        console.log("Request CallbackGasPrice:", blocklockRequest.directFundingFeePaid);
        console.log("Tx Gas used:", gasUsed);
        console.log("Tx Gas price (wei):", tx.gasprice);
        console.log("Tx Total cost (wei):", gasUsed * tx.gasprice);
        console.log(
            "Total withdrawable subscription balance (wei):", blocklockSender.s_withdrawableSubscriptionFeeNative()
        );
    }

    function test_invalidSignature_forSubscriptionRequest_reverts() public {
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

        // get request price
        uint32 callbackGasLimit = 100_000;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);

        // fund blocklock receiver contract
        uint256 aliceBalance = alice.balance;

        // create and fund subscription
        vm.prank(alice);
        mockBlocklockReceiver.createSubscriptionAndFundNative{value: requestPrice}();

        assertTrue(alice.balance == aliceBalance - (requestPrice), "Alice balance not debited");
        assertTrue(requestPrice > 0, "Invalid request price");

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = 100_000;
        uint256 requestId = mockBlocklockReceiver.createTimelockRequestWithSubscription(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].chainHeight, ciphertextDataUint[3 ether].ciphertext
        );

        // fulfill blocklock request
        /// @notice When we use less gas price, the total tx price including gas
        // limit for callback and external call from oracle is less than user payment or
        // calculated request price at request time
        // we don't use full user payment price as the gas price for callback from oracle.
        vm.txGasPrice(100_000);
        uint256 gasBefore = gasleft();

        vm.prank(admin);
        bytes memory invalidSignature =
            hex"02a3b2fa2c402d59e22a2f141e32a092603862a06a695cbfb574c440372a72cd0636ba8092f304e7701ae9abe910cb474edf0408d9dd78ea7f6f97b7f2464711";
        vm.expectRevert("Signature verification failed");
        decryptionSender.fulfillDecryptionRequest(
            requestId, ciphertextDataUint[3 ether].decryptionKey, invalidSignature
        );

        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 1);

        TypesLib.DecryptionRequest memory decryptionRequest = decryptionSender.getRequest(requestId);
        TypesLib.BlocklockRequest memory blocklockRequest = blocklockSender.getRequest(requestId);

        uint256 gasAfter = gasleft();
        uint256 gasUsed = gasBefore - gasAfter;
        console.log("Request CallbackGasLimit:", decryptionRequest.callbackGasLimit);
        console.log("Request CallbackGasPrice:", blocklockRequest.directFundingFeePaid);
        console.log("Tx Gas used:", gasUsed);
        console.log("Tx Gas price (wei):", tx.gasprice);
        console.log("Tx Total cost (wei):", gasUsed * tx.gasprice);

        assertTrue(
            !decryptionSender.hasErrored(requestId),
            "Callback to receiver contract should not fail due to lack of funds"
        );

        assertTrue(!decryptionRequest.isFulfilled, "Decryption logic should not have been reached");
        assertTrue(
            mockBlocklockReceiver.plainTextValue() != ciphertextDataUint[3 ether].plaintext,
            "Plaintext values mismatch after decryption"
        );
        assertTrue(mockBlocklockReceiver.requestId() == 1, "Request id in receiver contract is incorrect");

        // check no deductions from user and withdrawable amount in blocklock sender for admin
        console.log(blocklockRequest.directFundingFeePaid);
        assertTrue(
            blocklockSender.s_totalNativeBalance() == requestPrice,
            "We don't expect any funded subscriptions at this point"
        );

        assertTrue(
            blocklockSender.s_withdrawableSubscriptionFeeNative() == 0,
            "We don't expect any funded subscriptions at this point"
        );

        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSignature("InsufficientBalance()"));
        uint256 adminBalance = admin.balance;
        blocklockSender.withdrawDirectFundingFeesNative(payable(admin));
        assertTrue(admin.balance == adminBalance, "Admin balance should not change without withdrawing fees");
    }
}
