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

        setBlocklockSenderBillingConfiguration(
            maxGasLimit,
            gasAfterPaymentCalculation,
            fulfillmentFlatFeeNativePPM,
            weiPerUnitGas,
            blsPairingCheckOverhead,
            nativePremiumPercentage
        );
    }

    function test_deployment_configurations() public view {
        assertTrue(decryptionSender.hasRole(ADMIN_ROLE, admin));

        assert(address(signatureSchemeAddressProvider) != address(0));
        assert(address(blocklockSignatureScheme) != address(0));
        assert(address(decryptionSender) != address(0));
        assert(address(blocklockSender) != address(0));
        assert(address(mockBlocklockReceiver) != address(0));
        assert(address(decryptionSender.signatureSchemeAddressProvider()) != address(0));
    }

    function test_callsToBlocklockSender_shouldRevert_ifBlocklockSenderAddressIsIncorrect() public {
        vm.prank(alice);
        mockBlocklockReceiver = new MockBlocklockReceiver(admin);

        vm.prank(alice);
        vm.expectRevert();
        mockBlocklockReceiver.createSubscriptionAndFundNative{value: 0}();
    }

    function test_updateSignatureScheme() public {
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

    // helper functions
    function setBlocklockSenderBillingConfiguration(
        uint32 maxGasLimit,
        uint32 gasAfterPaymentCalculation,
        uint32 fulfillmentFlatFeeNativePPM,
        uint32 weiPerUnitGas,
        uint32 blsPairingCheckOverhead,
        uint8 nativePremiumPercentage
    ) internal {
        vm.prank(admin);
        blocklockSender.setConfig(
            maxGasLimit,
            gasAfterPaymentCalculation,
            fulfillmentFlatFeeNativePPM,
            weiPerUnitGas,
            blsPairingCheckOverhead,
            nativePremiumPercentage
        );
    }
}
