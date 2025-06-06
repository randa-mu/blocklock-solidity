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

/// @title DirectFunding test contract
/// @notice Tests for requests paid for via the direct funding route
contract DirectFundingTest is BlocklockTest {
    function test_FulfillDecryptionRequest_WithDirectFunding_Successfully() public {
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

        assertTrue(blocklockSender.s_configured(), "BlocklockSender not configured");
        assertFalse(blocklockSender.s_disabled(), "BlocklockSender is paused");

        // get request price
        uint32 callbackGasLimit = 500_000;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);

        assertTrue(requestPrice > 0, "Invalid request price");
        console.log("Estimated request price", requestPrice);

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = callbackGasLimit;
        (uint256 requestId,) = mockBlocklockReceiver.createTimelockRequestWithDirectFunding{value: requestPrice}(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].condition, ciphertextDataUint[3 ether].ciphertext
        );

        // fetch request information including callbackGasLimit from decryption sender
        TypesLib.DecryptionRequest memory decryptionRequest = decryptionSender.getRequest(requestId);

        // fetch request information from blocklock sender
        TypesLib.BlocklockRequest memory blocklockRequest = blocklockSender.getRequest(requestId);

        assertTrue(
            blocklockRequest.callbackGasLimit == requestCallbackGasLimit,
            "Stored callbackGasLimit does not match callbacGasLimit from user request"
        );

        assertTrue(blocklockRequest.subId == 0, "Direct funding request id should be zero");
        assertTrue(
            blocklockRequest.directFundingFeePaid > 0 && blocklockRequest.directFundingFeePaid == requestPrice,
            "Invalid price paid by user contract for request"
        );
        assertTrue(
            blocklockRequest.decryptionRequestId == requestId,
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
        console.log("Request CallbackGasLimit:", blocklockRequest.callbackGasLimit);
        console.log("Request CallbackGasPrice:", blocklockRequest.directFundingFeePaid);
        console.log("Tx Gas used:", gasUsed);
        console.log("Tx Gas price (wei):", tx.gasprice);
        console.log("Tx Total cost (wei):", gasUsed * tx.gasprice);

        assertTrue(
            !decryptionSender.hasErrored(requestId),
            "Payment collection in callback to receiver contract should not fail"
        );

        decryptionRequest = decryptionSender.getRequest(requestId);
        assertTrue(decryptionRequest.isFulfilled, "Decryption key not provided in decryption sender by offchain oracle");

        console.log("plaintext after decryption", mockBlocklockReceiver.plainTextValue());
        assertTrue(
            mockBlocklockReceiver.plainTextValue() == ciphertextDataUint[3 ether].plaintext,
            "Plaintext values mismatch after decryption"
        );
        assertTrue(mockBlocklockReceiver.requestId() == 1, "Request id in receiver contract is incorrect");

        // check deductions from user and withdrawable amount in blocklock sender for admin
        blocklockRequest = blocklockSender.getRequest(requestId);

        console.log("Direct funding fee paid", blocklockRequest.directFundingFeePaid);
        console.log(
            "Revenue after actual callback tx cost", blocklockRequest.directFundingFeePaid - (gasUsed * tx.gasprice)
        );

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

    function test_CallbackShouldNotRevert_IfInterfaceIsNotImplemented() public {
        assertTrue(blocklockSender.s_configured(), "BlocklockSender not configured");
        assertFalse(blocklockSender.s_disabled(), "BlocklockSender is paused");

        // get request price
        uint32 callbackGasLimit = 500_000;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = callbackGasLimit;
        uint256 requestId = blocklockSender.requestBlocklock{value: requestPrice}(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].condition, ciphertextDataUint[3 ether].ciphertext
        );

        // fetch request information including callbackGasLimit from decryption sender
        TypesLib.DecryptionRequest memory decryptionRequest = decryptionSender.getRequest(requestId);

        // fetch request information from blocklock sender
        TypesLib.BlocklockRequest memory blocklockRequest = blocklockSender.getRequest(requestId);

        assertTrue(
            blocklockRequest.callbackGasLimit == requestCallbackGasLimit,
            "Stored callbackGasLimit does not match callbacGasLimit from user request"
        );

        assertTrue(blocklockRequest.subId == 0, "Direct funding request id should be zero");
        assertTrue(
            blocklockRequest.directFundingFeePaid > 0 && blocklockRequest.directFundingFeePaid == requestPrice,
            "Invalid price paid by user contract for request"
        );
        assertTrue(
            blocklockRequest.decryptionRequestId == requestId,
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
        console.log("Request CallbackGasLimit:", blocklockRequest.callbackGasLimit);
        console.log("Request CallbackGasPrice:", blocklockRequest.directFundingFeePaid);
        console.log("Tx Gas used:", gasUsed);
        console.log("Tx Gas price (wei):", tx.gasprice);
        console.log("Tx Total cost (wei):", gasUsed * tx.gasprice);

        assertTrue(
            !decryptionSender.hasErrored(requestId),
            "Callback should not fail if calling address is not implementing the IBlocklockReceiver.receiveBlocklock interface"
        );

        decryptionRequest = decryptionSender.getRequest(requestId);
        assertTrue(decryptionRequest.isFulfilled, "Request should be marked as fulfilled");

        blocklockRequest = blocklockSender.getRequest(requestId);
        assertTrue(
            blocklockRequest.decryptionKey.length > 2,
            "Decryption key should be registered on-chain after fulfilling request"
        );

        // we can still take payment
        console.log("Direct funding fee paid", blocklockRequest.directFundingFeePaid);
        console.log(
            "Revenue after actual callback tx cost", blocklockRequest.directFundingFeePaid - (gasUsed * tx.gasprice)
        );

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

    function test_FulfillDecryptionRequest_WithLowCallbackGasLimit() public {
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

        assertTrue(blocklockSender.s_configured(), "BlocklockSender not configured");
        assertFalse(blocklockSender.s_disabled(), "BlocklockSender is paused");

        // get request price
        /// @dev this callbackGasLimit is not enough to cover for decrypt() function call in
        /// blocklock receiver contract, so the callback will revert and decryption will not work.
        /// but the outer call to fulfillDecryptionRequest will not fail.
        uint32 callbackGasLimit = 100_000;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);

        assertTrue(requestPrice > 0, "Invalid request price");
        console.log("Estimated request price", requestPrice);

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = callbackGasLimit;
        (uint256 requestId,) = mockBlocklockReceiver.createTimelockRequestWithDirectFunding{value: requestPrice}(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].condition, ciphertextDataUint[3 ether].ciphertext
        );

        // fetch request information including callbackGasLimit from decryption sender
        TypesLib.DecryptionRequest memory decryptionRequest = decryptionSender.getRequest(requestId);

        // fetch request information from blocklock sender
        TypesLib.BlocklockRequest memory blocklockRequest = blocklockSender.getRequest(requestId);

        assertTrue(
            blocklockRequest.callbackGasLimit == requestCallbackGasLimit,
            "Stored callbackGasLimit does not match callbacGasLimit from user request"
        );

        assertTrue(blocklockRequest.subId == 0, "Direct funding request id should be zero");
        assertTrue(
            blocklockRequest.directFundingFeePaid > 0 && blocklockRequest.directFundingFeePaid == requestPrice,
            "Invalid price paid by user contract for request"
        );
        assertTrue(
            blocklockRequest.decryptionRequestId == requestId,
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
        console.log("Request CallbackGasLimit:", blocklockRequest.callbackGasLimit);
        console.log("Request CallbackGasPrice:", blocklockRequest.directFundingFeePaid);
        console.log("Tx Gas used:", gasUsed);
        console.log("Tx Gas price (wei):", tx.gasprice);
        console.log("Tx Total cost (wei):", gasUsed * tx.gasprice);

        assertTrue(
            !decryptionSender.hasErrored(requestId),
            "Payment collection in callback to receiver contract should not fail"
        );

        decryptionRequest = decryptionSender.getRequest(requestId);
        assertTrue(decryptionRequest.isFulfilled, "Decryption key not provided in decryption sender by offchain oracle");

        console.log("plaintext after decryption", mockBlocklockReceiver.plainTextValue());
        assertTrue(
            mockBlocklockReceiver.plainTextValue() != ciphertextDataUint[3 ether].plaintext,
            "Decryption fails with low callback gas limit set in request"
        );
        assertTrue(mockBlocklockReceiver.requestId() == 1, "Request id in receiver contract is incorrect");

        // check deductions from user and withdrawable amount in blocklock sender for admin
        blocklockRequest = blocklockSender.getRequest(requestId);

        console.log("Direct funding fee paid", blocklockRequest.directFundingFeePaid);
        console.log(
            "Revenue after actual callback tx cost", blocklockRequest.directFundingFeePaid - (gasUsed * tx.gasprice)
        );

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

    function test_FulfillDecryptionRequest_WithZeroCallbackGasLimit() public {
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

        assertTrue(blocklockSender.s_configured(), "BlocklockSender not configured");
        assertFalse(blocklockSender.s_disabled(), "BlocklockSender is paused");

        // get request price
        /// @dev this callbackGasLimit is not enough to cover for decrypt() function call in
        /// blocklock receiver contract, so the callback will revert and decryption will not work.
        /// but the outer call to fulfillDecryptionRequest will not fail.
        uint32 callbackGasLimit = 0;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);

        assertTrue(requestPrice > 0, "Invalid request price");
        console.log("Estimated request price", requestPrice);

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = callbackGasLimit;
        (uint256 requestId,) = mockBlocklockReceiver.createTimelockRequestWithDirectFunding{value: requestPrice}(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].condition, ciphertextDataUint[3 ether].ciphertext
        );

        // fetch request information including callbackGasLimit from decryption sender
        TypesLib.DecryptionRequest memory decryptionRequest = decryptionSender.getRequest(requestId);

        // fetch request information from blocklock sender
        TypesLib.BlocklockRequest memory blocklockRequest = blocklockSender.getRequest(requestId);

        assertTrue(
            blocklockRequest.callbackGasLimit == requestCallbackGasLimit,
            "Stored callbackGasLimit does not match callbacGasLimit from user request"
        );

        assertTrue(blocklockRequest.subId == 0, "Direct funding request id should be zero");
        assertTrue(
            blocklockRequest.directFundingFeePaid > 0 && blocklockRequest.directFundingFeePaid == requestPrice,
            "Invalid price paid by user contract for request"
        );
        assertTrue(
            blocklockRequest.decryptionRequestId == requestId,
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
        console.log("Request CallbackGasLimit:", blocklockRequest.callbackGasLimit);
        console.log("Request CallbackGasPrice:", blocklockRequest.directFundingFeePaid);
        console.log("Tx Gas used:", gasUsed);
        console.log("Tx Gas price (wei):", tx.gasprice);
        console.log("Tx Total cost (wei):", gasUsed * tx.gasprice);

        assertTrue(
            !decryptionSender.hasErrored(requestId),
            "Payment collection in callback to receiver contract should not fail"
        );

        decryptionRequest = decryptionSender.getRequest(requestId);
        assertTrue(decryptionRequest.isFulfilled, "Decryption key not provided in decryption sender by offchain oracle");

        console.log("plaintext after decryption", mockBlocklockReceiver.plainTextValue());
        assertTrue(
            mockBlocklockReceiver.plainTextValue() != ciphertextDataUint[3 ether].plaintext,
            "Decryption fails with low callback gas limit set in request"
        );
        assertTrue(mockBlocklockReceiver.requestId() == 1, "Request id in receiver contract is incorrect");

        // check deductions from user and withdrawable amount in blocklock sender for admin
        blocklockRequest = blocklockSender.getRequest(requestId);

        console.log("Direct funding fee paid", blocklockRequest.directFundingFeePaid);
        console.log(
            "Revenue after actual callback tx cost", blocklockRequest.directFundingFeePaid - (gasUsed * tx.gasprice)
        );

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

    function test_FulfillDecryptionRequest_WithRevertingReceiver() public {
        vm.prank(alice);
        MockBlocklockRevertingReceiver mockBlocklockReceiver =
            new MockBlocklockRevertingReceiver(address(blocklockSender));

        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

        assertTrue(blocklockSender.s_configured(), "BlocklockSender not configured");
        assertFalse(blocklockSender.s_disabled(), "BlocklockSender is paused");

        // get request price
        uint32 callbackGasLimit = 100_000;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);

        assertTrue(requestPrice > 0, "Invalid request price");
        console.log("Estimated request price", requestPrice);

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = callbackGasLimit;
        (uint256 requestId,) = mockBlocklockReceiver.createTimelockRequestWithDirectFunding{value: requestPrice}(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].condition, ciphertextDataUint[3 ether].ciphertext
        );

        // fetch request information including callbackGasLimit from decryption sender
        TypesLib.DecryptionRequest memory decryptionRequest = decryptionSender.getRequest(requestId);

        // fetch request information from blocklock sender
        TypesLib.BlocklockRequest memory blocklockRequest = blocklockSender.getRequest(requestId);

        assertTrue(
            blocklockRequest.callbackGasLimit == requestCallbackGasLimit,
            "Stored callbackGasLimit does not match callbacGasLimit from user request"
        );

        assertTrue(blocklockRequest.subId == 0, "Direct funding request id should be zero");
        assertTrue(
            blocklockRequest.directFundingFeePaid > 0 && blocklockRequest.directFundingFeePaid == requestPrice,
            "Invalid price paid by user contract for request"
        );
        assertTrue(
            blocklockRequest.decryptionRequestId == requestId,
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
        console.log("Request CallbackGasLimit:", blocklockRequest.callbackGasLimit);
        console.log("Request CallbackGasPrice:", blocklockRequest.directFundingFeePaid);
        console.log("Tx Gas used:", gasUsed);
        console.log("Tx Gas price (wei):", tx.gasprice);
        console.log("Tx Total cost (wei):", gasUsed * tx.gasprice);

        assertTrue(
            !decryptionSender.hasErrored(requestId),
            "Payment collection in callback to receiver contract should not fail"
        );

        decryptionRequest = decryptionSender.getRequest(requestId);
        assertTrue(decryptionRequest.isFulfilled, "Decryption key not provided in decryption sender by offchain oracle");
        assertTrue(
            mockBlocklockReceiver.plainTextValue() != ciphertextDataUint[3 ether].plaintext,
            "Plaintext values mismatch after revert in callback contract logic"
        );
        assertTrue(mockBlocklockReceiver.requestId() == 1, "Request id in receiver contract is incorrect");

        // check deductions from user and withdrawable amount in blocklock sender for admin
        blocklockRequest = blocklockSender.getRequest(requestId);

        console.log("Direct funding fee paid", blocklockRequest.directFundingFeePaid);
        console.log(
            "Revenue after actual callback tx cost", blocklockRequest.directFundingFeePaid - (gasUsed * tx.gasprice)
        );

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

    function test_FulfillDecryptionRequest_WithInvalidRequestId_ShouldRevert() public {
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

        // get request price
        uint32 callbackGasLimit = 100_000;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);

        assertTrue(requestPrice > 0, "Invalid request price");

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = callbackGasLimit;
        (uint256 requestId,) = mockBlocklockReceiver.createTimelockRequestWithDirectFunding{value: requestPrice}(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].condition, ciphertextDataUint[3 ether].ciphertext
        );

        vm.expectRevert("No pending request with specified requestId");
        vm.prank(admin);
        decryptionSender.fulfillDecryptionRequest(
            requestId + 1, ciphertextDataUint[3 ether].decryptionKey, ciphertextDataUint[3 ether].signature
        );

        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 1);
    }

    function test_FulfillDecryptionRequest_WithInvalidSignature_ShouldRevert() public {
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

        // get request price
        uint32 callbackGasLimit = 100_000;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);

        assertTrue(requestPrice > 0, "Invalid request price");

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = callbackGasLimit;
        (uint256 requestId,) = mockBlocklockReceiver.createTimelockRequestWithDirectFunding{value: requestPrice}(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].condition, ciphertextDataUint[3 ether].ciphertext
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
        console.log("Request CallbackGasLimit:", blocklockRequest.callbackGasLimit);
        console.log("Request CallbackGasPrice:", blocklockRequest.directFundingFeePaid);
        console.log("Tx Gas used:", gasUsed);
        console.log("Tx Gas price (wei):", tx.gasprice);
        console.log("Tx Total cost (wei):", gasUsed * tx.gasprice);

        assertTrue(
            !decryptionSender.hasErrored(requestId),
            "Payment collection in callback to receiver contract should not be called"
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
            blocklockSender.s_totalNativeBalance() == 0, "We don't expect any funded subscriptions at this point"
        );
        assertTrue(
            blocklockSender.s_withdrawableDirectFundingFeeNative() != blocklockRequest.directFundingFeePaid
                && blocklockSender.s_withdrawableDirectFundingFeeNative() == 0,
            "Request price paid should not be withdrawable by admin at this point"
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

    function test_FulfillDecryptionRequest_WithUnauthorisedCaller_ShouldRevert() public {
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

        // get request price
        uint32 callbackGasLimit = 100_000;
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);

        assertTrue(requestPrice > 0, "Invalid request price");

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = callbackGasLimit;
        (uint256 requestId,) = mockBlocklockReceiver.createTimelockRequestWithDirectFunding{value: requestPrice}(
            requestCallbackGasLimit, ciphertextDataUint[3 ether].condition, ciphertextDataUint[3 ether].ciphertext
        );

        vm.prank(admin);
        vm.expectRevert();
        mockBlocklockReceiver.receiveBlocklock(requestId, ciphertextDataUint[3 ether].decryptionKey);

        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 1);
    }
}
