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
    function test_fulfillBlocklock_directFunding_request() public {
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

        assertTrue(blocklockSender.s_configured(), "BlocklockSender not configured");
        assertFalse(blocklockSender.s_disabled(), "BlocklockSender is paused");

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
        console.log("Estimated request price", requestPrice);

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
                == requestCallbackGasLimit + callbackGasOverhead + callbackWithDecryptionAndSignatureVerificationOverhead,
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

        assertTrue(!decryptionSender.hasErrored(requestId), "Callback to receiver contract should not fail");

        decryptionRequest = decryptionSender.getRequest(requestId);
        assertTrue(decryptionRequest.isFulfilled, "Decryption key not provided in decryption sender by offchain oracle");
        assertTrue(
            mockBlocklockReceiver.plainTextValue() == ciphertextDataUint[3 ether].plaintext,
            "Plaintext values mismatch after decryption"
        );
        assertTrue(mockBlocklockReceiver.requestId() == 1, "Request id in receiver contract is incorrect");

        // check deductions from user and withdrawable amount in blocklock sender for admin
        blocklockRequest = blocklockSender.getRequest(requestId);

        console.log("Direct funding fee paid", blocklockRequest.directFundingFeePaid);
        console.log(
            "Overhead after actual callback tx cost", blocklockRequest.directFundingFeePaid - (gasUsed * tx.gasprice)
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

    function test_fulfillBlocklock_DirectFundingRequest_withRevertingReceiver() public {
        vm.prank(alice);
        MockBlocklockRevertingReceiver mockBlocklockReceiver = new MockBlocklockRevertingReceiver(address(blocklockSender));
        
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

        assertTrue(blocklockSender.s_configured(), "BlocklockSender not configured");
        assertFalse(blocklockSender.s_disabled(), "BlocklockSender is paused");

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
        console.log("Estimated request price", requestPrice);

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
                == requestCallbackGasLimit + callbackGasOverhead + callbackWithDecryptionAndSignatureVerificationOverhead,
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

        assertTrue(!decryptionSender.hasErrored(requestId), "Callback to receiver contract should not fail");

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
            "Overhead after actual callback tx cost", blocklockRequest.directFundingFeePaid - (gasUsed * tx.gasprice)
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

    function test_invalidRequestId_forDirectFundingRequest_reverts() public {
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

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

        vm.expectRevert("No pending request with specified requestID");
        vm.prank(admin);
        decryptionSender.fulfillDecryptionRequest(
            requestId + 1, ciphertextDataUint[3 ether].decryptionKey, ciphertextDataUint[3 ether].signature
        );

        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 1);
    }

    function test_invalidSignature_forDirectFundingRequest_reverts() public {
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

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

        assertTrue(!decryptionSender.hasErrored(requestId), "Callback to receiver contract should not fail");

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

    function test_fulfillWithUnauthorisedCaller_reverts() public {
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

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
}
