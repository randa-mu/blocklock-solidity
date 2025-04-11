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

import {TypesLib} from "../../src/libraries/TypesLib.sol";
import {BLS} from "../../src/libraries/BLS.sol";

/// @title BlocklockTest test contract
/// @dev Onchain conditional encryption tests
contract BlocklockTest is Deployment {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    uint256 plaintext = 3 ether;

    TypesLib.Ciphertext ciphertext = TypesLib.Ciphertext({
        u: BLS.PointG2({
            x: [
                14142380308423906610328325205633754694002301558654408701934220147059967542660,
                4795984740938726483924720262587026838890051381570343702421443260575124596446
            ],
            y: [
                13301122453285478420056122708237526083484415709254283392885579853639158169617,
                11125759247493978573666410429063118092803139083876927879642973106997490249635
            ]
        }),
        v: hex"63f745f4240f4708db37b0fa0e40309a37ab1a65f9b1be4ac716a347d4fe57fe",
        w: hex"e8aadd66a9a67c00f134b1127b7ef85046308c340f2bb7cee431bd7bfe950bd4"
    });

    bytes signature =
        hex"02b3b2fa2c402d59e22a2f141e32a092603862a06a695cbfb574c440372a72cd0636ba8092f304e7701ae9abe910cb474edf0408d9dd78ea7f6f97b7f2464711";

    bytes decryptionKey = hex"7ec49d8f06b34d8d6b2e060ea41652f25b1325fafb041bba9cf24f094fbca259";

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

    // without gas limit and gas price specified by offchain oracle
    function test_FulfilledBlocklockDirectFundingRequest() public {
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

        // set blocklockSender contract config
        // fixme move setConfig to helper
        uint32 maxGasLimit = 500_000;
        uint32 gasAfterPaymentCalculation = 400_000;
        uint32 fulfillmentFlatFeeNativePPM = 1_000_000;
        uint8 nativePremiumPercentage = 10;

        vm.prank(admin);
        blocklockSender.setConfig(
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
            mockBlocklockReceiver.createTimelockRequestWithDirectFunding(requestCallbackGasLimit, 13, ciphertext);

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
            decryptionRequest.callbackGasLimit == requestCallbackGasLimit + callbackGasOverhead + decryptionAndSignatureVerificationOverhead,
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
        // fixme review - when we use less gas price, the total tx price including gas
        // limit for callback and external call from oracle is less than user payment or
        // calculated request price at request time
        // we don't use user payment as the gas price for callback from oracle.
        vm.txGasPrice(100_000);
        uint256 gasBefore = gasleft();

        vm.startPrank(admin);
        decryptionSender.fulfillDecryptionRequest(requestId, decryptionKey, signature);

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
        assertTrue(mockBlocklockReceiver.plainTextValue() == plaintext, "Plaintext values mismatch after decryption");
        assertTrue(mockBlocklockReceiver.requestId() == 1, "Request id in receiver contract is incorrect");

        // check deductions from user and withdrawable amount in blocklock sender for admin
        blocklockRequest = blocklockSender.getRequest(requestId);

        console.log(blocklockRequest.directFundingFeePaid);
        assertTrue(blocklockSender.s_totalNativeBalance() == 0, "We don't expect any funded subscriptions at this point");
        assertTrue(blocklockSender.s_withdrawableNative() == blocklockRequest.directFundingFeePaid, "Request price paid should be withdrawable by admin at this point");
    }

    // function test_UnauthorisedCaller() public {
    //     assert(mockBlocklockReceiver.plainTextValue() == 0);
    //     assert(mockBlocklockReceiver.requestId() == 0);

    //     uint256 requestId = mockBlocklockReceiver.createTimelockRequest(13, ciphertext);

    //     vm.startPrank(owner);
    //     vm.expectRevert("Only timelock contract can call this.");
    //     mockBlocklockReceiver.receiveBlocklock(requestId, decryptionKey);

    //     assert(mockBlocklockReceiver.plainTextValue() == 0);
    //     assert(mockBlocklockReceiver.requestId() == 1);
    //     vm.stopPrank();
    // }

    // function test_InvalidRequestId() public {
    //     assert(mockBlocklockReceiver.plainTextValue() == 0);
    //     assert(mockBlocklockReceiver.requestId() == 0);

    //     uint256 requestId = mockBlocklockReceiver.createTimelockRequest(13, ciphertext);

    //     vm.startPrank(owner);

    //     vm.expectRevert("No request with specified requestID");
    //     decryptionSender.fulfillDecryptionRequest(requestId + 1, decryptionKey, signature);

    //     assert(mockBlocklockReceiver.plainTextValue() == 0);
    //     assert(mockBlocklockReceiver.requestId() == 1);

    //     vm.stopPrank();
    // }

    // function test_InvalidSignature() public {
    //     assert(mockBlocklockReceiver.plainTextValue() == 0);
    //     assert(mockBlocklockReceiver.requestId() == 0);

    //     uint256 requestId = mockBlocklockReceiver.createTimelockRequest(13, ciphertext);

    //     vm.startPrank(owner);
    //     bytes memory invalidSignature =
    //         hex"02a3b2fa2c402d59e22a2f141e32a092603862a06a695cbfb574c440372a72cd0636ba8092f304e7701ae9abe910cb474edf0408d9dd78ea7f6f97b7f2464711";
    //     vm.expectRevert("Signature verification failed");
    //     decryptionSender.fulfillDecryptionRequest(requestId, decryptionKey, invalidSignature);

    //     assert(mockBlocklockReceiver.plainTextValue() == 0);
    //     assert(mockBlocklockReceiver.requestId() == 1);
    //     vm.stopPrank();
    // }
}
