// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

// helpers
import {Base} from "./Base.t.sol";
import {BLS} from "../../../src/libraries/BLS.sol";
import {TypesLib} from "../../../src/libraries/TypesLib.sol";
import {UUPSProxy} from "../../../src/proxy/UUPSProxy.sol";

// core contracts
import {SignatureSchemeAddressProvider} from "../../../src/signature-schemes/SignatureSchemeAddressProvider.sol";
import {BlocklockSender} from "../../../src/blocklock/BlocklockSender.sol";
import {BlocklockSignatureScheme} from "../../../src/signature-schemes/BlocklockSignatureScheme.sol";
import {DecryptionSender} from "../../../src/decryption-requests/DecryptionSender.sol";

// mock contracts
import {MockBlocklockReceiver} from "../../../src/mocks/MockBlocklockReceiver.sol";
import {MockBlocklockRevertingReceiver} from "../../../src/mocks/MockBlocklockRevertingReceiver.sol";

/// @title Deployment test contract
/// @dev Deploys the core smart contracts needed by other tests.
abstract contract Deployment is Base {
    string internal SCHEME_ID = "BN254-BLS-BLOCKLOCK";

    /// @dev This prevents out of gas errors when doing signature pairing check
    /// for decryption during callback
    uint32 internal constant callbackWithDecryptionAndSignatureVerificationOverhead = 800_000;

    BLS.PointG2 internal pk = BLS.PointG2({
        x: [
            17445541620214498517833872661220947475697073327136585274784354247720096233162,
            18268991875563357240413244408004758684187086817233527689475815128036446189503
        ],
        y: [
            11401601170172090472795479479864222172123705188644469125048759621824127399516,
            8044854403167346152897273335539146380878155193886184396711544300199836788154
        ]
    });

    function setUp() public virtual override {
        // setup base test
        super.setUp();
    }

    function deployContracts()
        internal
        returns (
            SignatureSchemeAddressProvider signatureSchemeAddressProvider,
            BlocklockSignatureScheme blocklockSignatureScheme,
            DecryptionSender decryptionSender,
            BlocklockSender blocklockSender,
            MockBlocklockReceiver mockBlocklockReceiver
        )
    {
        vm.prank(admin);
        DecryptionSender decryptionSender_implementation = new DecryptionSender();

        vm.prank(admin);
        UUPSProxy decryptionSender_proxy = new UUPSProxy(address(decryptionSender_implementation), "");

        decryptionSender = DecryptionSender(address(decryptionSender_proxy));

        vm.prank(admin);
        BlocklockSender blocklockSender_implementation = new BlocklockSender();

        vm.prank(admin);
        UUPSProxy blocklockSender_proxy = new UUPSProxy(address(blocklockSender_implementation), "");

        blocklockSender = BlocklockSender(address(blocklockSender_proxy));

        vm.prank(alice);
        mockBlocklockReceiver = new MockBlocklockReceiver(address(blocklockSender_proxy));

        vm.prank(admin);
        signatureSchemeAddressProvider = new SignatureSchemeAddressProvider(admin);

        vm.prank(admin);
        blocklockSignatureScheme = new BlocklockSignatureScheme(pk.x, pk.y);

        vm.prank(admin);
        signatureSchemeAddressProvider.updateSignatureScheme(SCHEME_ID, address(blocklockSignatureScheme));

        vm.prank(admin);
        decryptionSender.initialize(admin, address(signatureSchemeAddressProvider));

        vm.prank(admin);
        blocklockSender.initialize(admin, address(decryptionSender));
    }

    function deployAndFundReceiverWithSubscription(address owner, address blocklockSenderProxy, uint256 subBalance)
        internal
        returns (MockBlocklockReceiver mockBlocklockReceiver)
    {
        vm.prank(owner);
        mockBlocklockReceiver = new MockBlocklockReceiver(blocklockSenderProxy);

        vm.prank(owner);
        mockBlocklockReceiver.createSubscriptionAndFundNative{value: subBalance}();
    }

    function deployBlocklockReceiver(address owner, address blocklockSenderProxy)
        internal
        returns (MockBlocklockReceiver mockBlocklockReceiver)
    {
        vm.prank(owner);
        mockBlocklockReceiver = new MockBlocklockReceiver(blocklockSenderProxy);
    }
}
