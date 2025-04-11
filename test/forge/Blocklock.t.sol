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
        uint32 requestCallbackGasLimit = 100000;
        (uint256 requestId,) =
            mockBlocklockReceiver.createTimelockRequestWithDirectFunding(requestCallbackGasLimit, 13, ciphertextDataUint[3 ether].ciphertext);

        // fetch request information including callbackGasLimit from decryption sender
        TypesLib.DecryptionRequest memory decryptionRequest = decryptionSender.getRequest(requestId);

        /// @dev Overhead for EIP-150
        uint256 callbackGasOverhead = requestCallbackGasLimit / 63 + 1;

        /// @dev This prevents out of gas errors when doing signature pairing check
        /// for decryption during callback
        uint32 decryptionAndSignatureVerificationOverhead = 500_000;

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
        decryptionSender.fulfillDecryptionRequest(requestId, ciphertextDataUint[3 ether].decryptionKey, ciphertextDataUint[3 ether].signature);

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
        assertTrue(mockBlocklockReceiver.plainTextValue() == ciphertextDataUint[3 ether].plaintext, "Plaintext values mismatch after decryption");
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
        uint32 requestCallbackGasLimit = 100000;
        (uint256 requestId,) =
            mockBlocklockReceiver.createTimelockRequestWithDirectFunding(requestCallbackGasLimit, 13, ciphertextDataUint[3 ether].ciphertext);

        vm.startPrank(admin);
        vm.expectRevert("Only blocklock contract can call");
        mockBlocklockReceiver.receiveBlocklock(requestId, ciphertextDataUint[3 ether].decryptionKey);

        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 1);
        vm.stopPrank();
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
        uint32 requestCallbackGasLimit = 100000;
        (uint256 requestId,) =
            mockBlocklockReceiver.createTimelockRequestWithDirectFunding(requestCallbackGasLimit, 13, ciphertextDataUint[3 ether].ciphertext);

        vm.expectRevert("No request with specified requestID");
        vm.prank(admin);
        decryptionSender.fulfillDecryptionRequest(requestId + 1, ciphertextDataUint[3 ether].decryptionKey, ciphertextDataUint[3 ether].signature);

        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 1);

        vm.stopPrank();
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
        uint32 requestCallbackGasLimit = 100000;
        (uint256 requestId,) =
            mockBlocklockReceiver.createTimelockRequestWithDirectFunding(requestCallbackGasLimit, 13, ciphertextDataUint[3 ether].ciphertext);

        vm.startPrank(admin);
        bytes memory invalidSignature =
            hex"02a3b2fa2c402d59e22a2f141e32a092603862a06a695cbfb574c440372a72cd0636ba8092f304e7701ae9abe910cb474edf0408d9dd78ea7f6f97b7f2464711";
        vm.expectRevert("Signature verification failed");
        decryptionSender.fulfillDecryptionRequest(requestId, ciphertextDataUint[3 ether].decryptionKey, invalidSignature);

        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 1);
        vm.stopPrank();
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
