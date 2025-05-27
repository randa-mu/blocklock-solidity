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
    MockBlocklockRevertingReceiver
} from "./Deployment.t.sol";

import {TypesLib, BLS} from "./Base.t.sol";

/// @title BlocklockTest test contract
/// @dev Onchain conditional encryption tests
contract BlocklockTest is Deployment {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    SignatureSchemeAddressProvider internal signatureSchemeAddressProvider;
    BlocklockSignatureScheme internal blocklockSignatureScheme;
    DecryptionSender internal decryptionSender;
    BlocklockSender internal blocklockSender;
    MockBlocklockReceiver internal mockBlocklockReceiver;

    function setUp() public override {
        // setup base test
        super.setUp();

        (
            signatureSchemeAddressProvider,
            blocklockSignatureScheme,
            decryptionSender,
            blocklockSender,
            mockBlocklockReceiver
        ) = deployContracts();

        // set blocklockSender contract config
        uint32 maxGasLimit = 500_000;
        uint32 gasAfterPaymentCalculation = 400_000;
        uint32 fulfillmentFlatFeeNativePPM = 1_000_000;
        uint32 weiPerUnitGas = 0.003 gwei;
        uint32 blsPairingCheckOverhead = 800_000;
        uint8 nativePremiumPercentage = 10;
        uint16 gasForExactCallCheck = 5000;

        setBlocklockSenderUserBillingConfiguration(
            maxGasLimit,
            gasAfterPaymentCalculation,
            fulfillmentFlatFeeNativePPM,
            weiPerUnitGas,
            blsPairingCheckOverhead,
            nativePremiumPercentage,
            gasForExactCallCheck
        );
    }

    function test_Deployment_Configurations() public view {
        assertTrue(decryptionSender.hasRole(ADMIN_ROLE, admin));

        assert(address(signatureSchemeAddressProvider) != address(0));
        assert(address(blocklockSignatureScheme) != address(0));
        assert(address(decryptionSender) != address(0));
        assert(address(blocklockSender) != address(0));
        assert(address(mockBlocklockReceiver) != address(0));
        assert(address(decryptionSender.signatureSchemeAddressProvider()) != address(0));

        console.logBytes(blocklockSignatureScheme.DST());
        console.logString(string(blocklockSignatureScheme.DST()));
        console.logString(string(blocklockSender.DST_H1_G1()));
        console.logString(string(blocklockSender.DST_H2()));
        console.logString(string(blocklockSender.DST_H3()));
        console.logString(string(blocklockSender.DST_H4()));
    }

    function test_CallsToBlocklockSender_ShouldRevert_IfBlocklockSenderAddressIsIncorrect() public {
        vm.prank(alice);
        mockBlocklockReceiver = new MockBlocklockReceiver(admin);

        vm.prank(alice);
        vm.expectRevert();
        mockBlocklockReceiver.createSubscriptionAndFundNative{value: 0}();
    }

    function test_Update_SignatureScheme() public {
        // non-zero address with zero code
        string memory bn254_schemeID = "BN254";
        address schemeAddr = makeAddr(bn254_schemeID);
        assertTrue(schemeAddr != address(0), "schemeAddr should not be zero address");
        assertTrue(schemeAddr.code.length == 0, "schemeAddr should not have any code");
        vm.prank(admin);
        vm.expectRevert("Invalid contract address for schemeAddress");
        signatureSchemeAddressProvider.updateSignatureScheme(bn254_schemeID, schemeAddr);

        // non-zero address with non-zero code
        schemeAddr = address(blocklockSignatureScheme);
        assertTrue(schemeAddr != address(0), "schemeAddr address should not be zero address");
        assertTrue(schemeAddr.code.length > 0, "schemeAddr address should have code");
        vm.prank(admin);
        signatureSchemeAddressProvider.updateSignatureScheme(bn254_schemeID, schemeAddr);
        assertTrue(signatureSchemeAddressProvider.getSignatureSchemeAddress(bn254_schemeID) == schemeAddr);

        // replacing existing scheme contract reverts
        schemeAddr = address(blocklockSender);
        vm.prank(admin);
        vm.expectRevert("Scheme already added for schemeID");
        signatureSchemeAddressProvider.updateSignatureScheme(bn254_schemeID, schemeAddr);
        assertTrue(
            signatureSchemeAddressProvider.getSignatureSchemeAddress(bn254_schemeID) != schemeAddr,
            "Scheme contract address should not have been replaced"
        );

        // zero address with zero code
        vm.prank(admin);
        vm.expectRevert("Invalid contract address for schemeAddress");
        signatureSchemeAddressProvider.updateSignatureScheme(bn254_schemeID, address(0));
    }

    function test_EstimatedRequestPrice_Increases_WithCallbackGasLimit() public view {
        uint32 callbackGasLimit = 100_000;
        // request price should increase if callbackGasLimit increases
        uint256 requestPrice = blocklockSender.calculateRequestPriceNative(callbackGasLimit);
        callbackGasLimit = 200_000;
        assertTrue(
            requestPrice < blocklockSender.calculateRequestPriceNative(callbackGasLimit),
            "Estimated request price should increase if callback gas limit increases"
        );
    }

    function test_EstimatedRequestPrice_Increases_WithGasPrice() public view {
        uint32 callbackGasLimit = 100_000;
        uint32 gasPrice = 100 wei;
        // request price should increase if gas price increases
        uint256 requestPrice = blocklockSender.estimateRequestPriceNative(callbackGasLimit, gasPrice);
        gasPrice = 200 wei;
        assertTrue(
            requestPrice < blocklockSender.estimateRequestPriceNative(callbackGasLimit, gasPrice),
            "Estimated request price should increase if callback gas price increases"
        );
    }

    // helper functions
    function setBlocklockSenderUserBillingConfiguration(
        uint32 maxGasLimit,
        uint32 gasAfterPaymentCalculation,
        uint32 fulfillmentFlatFeeNativePPM,
        uint32 weiPerUnitGas,
        uint32 blsPairingCheckOverhead,
        uint8 nativePremiumPercentage,
        uint32 gasForCallExactCheck
    ) internal {
        vm.prank(admin);
        blocklockSender.setConfig(
            maxGasLimit,
            gasAfterPaymentCalculation,
            fulfillmentFlatFeeNativePPM,
            weiPerUnitGas,
            blsPairingCheckOverhead,
            nativePremiumPercentage,
            gasForCallExactCheck
        );
    }
}
