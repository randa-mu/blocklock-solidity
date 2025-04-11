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

        (
            signatureSchemeAddressProvider,
            blocklockScheme,
            decryptionSender,
            blocklockSender,
            mockBlocklockReceiver
        ) = deployContracts();
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

    function test_FulfilledBlocklockDirectFundingRequest() public {
        assert(mockBlocklockReceiver.plainTextValue() == 0);
        assert(mockBlocklockReceiver.requestId() == 0);

        // set blocklockSender contract config
        // fixme move setConfig to helper
        uint32 maxGasLimit = 5_000_000;
        uint32 gasAfterPaymentCalculation = 10_000;
        uint32 fulfillmentFlatFeeNativePPM = 500;
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
        mockBlocklockReceiver.fundContractNative{value: 1 ether}();
        
        assertTrue(mockBlocklockReceiver.getBalance() == 1 ether, "Incorrect ether balance for blocklock receiver contract");
        assertTrue(alice.balance == aliceBalance - 1 ether, "Alice balance not debited");
        assertTrue(requestPrice < 1 ether, "Funded amount less than or equal to request price");

        // make blocklock request
        vm.prank(alice);
        uint32 requestCallbackGasLimit = 100000;
        (uint256 requestId, ) = mockBlocklockReceiver.createTimelockRequestWithDirectFunding(requestCallbackGasLimit, 13, ciphertext);

        // fetch request information including callbackGasLimit from decryption sender
        TypesLib.DecryptionRequest memory decryptionRequest = decryptionSender.getRequest(requestId);
        console.log(decryptionRequest.callbackGasLimit);

        uint256 callbackGasOverhead = requestCallbackGasLimit / 63 + 1;
        assertTrue(decryptionRequest.callbackGasLimit > requestCallbackGasLimit, "Gas buffer for _getEIP150Overhead() not added to callbackGasLimit from user request");
        assertTrue(decryptionRequest.callbackGasLimit == requestCallbackGasLimit + callbackGasOverhead, "Incorrect Gas buffer for _getEIP150Overhead() added to callbackGasLimit from user request");

        // fulfill blocklock request
        // vm.startPrank(admin);
        // decryptionSender.fulfillDecryptionRequest(requestId, decryptionKey, signature);

        // assert(mockBlocklockReceiver.plainTextValue() == plaintext);
        // assert(mockBlocklockReceiver.requestId() == 1);
        // vm.stopPrank();
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
