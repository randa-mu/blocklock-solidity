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

    function test_deployment_configurations() public view {
        assertTrue(decryptionSender.hasRole(ADMIN_ROLE, admin));

        assert(address(signatureSchemeAddressProvider) != address(0));
        assert(address(blocklockScheme) != address(0));
        assert(address(decryptionSender) != address(0));
        assert(address(blocklockSender) != address(0));
        assert(address(mockBlocklockReceiver) != address(0));
        assert(address(decryptionSender.signatureSchemeAddressProvider()) != address(0));
    }

    function test_callsToBlocklockSender_shouldRevert_ifBlocklockSenderAddressIsIncorrect() public {
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
