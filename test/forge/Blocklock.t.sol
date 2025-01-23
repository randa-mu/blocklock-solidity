// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console} from "forge-std/Test.sol";

import {SignatureSchemeAddressProvider} from "../../src/signature-schemes/SignatureSchemeAddressProvider.sol";
import {SignatureSender} from "../../src/signature-requests/SignatureSender.sol";
import {BlocklockSender} from "../../src/blocklock/BlocklockSender.sol";
import {BlocklockSignatureScheme} from "../../src/blocklock/BlocklockSignatureScheme.sol";
import {DecryptionSender} from "../../src/decryption-requests/DecryptionSender.sol";
import {BLS} from "../../src/libraries/BLS.sol";
import {TypesLib} from "../../src/libraries/TypesLib.sol";
import {UUPSProxy} from "../../src/proxy/UUPSProxy.sol";

contract SimpleAuctionTest is Test {
    UUPSProxy decryptionSenderProxy;
    UUPSProxy blocklockSenderProxy;

    SignatureSender public sigSender;
    DecryptionSender public decryptionSender;
    BlocklockSender public tlock;

    string SCHEME_ID = "BN254-BLS-BLOCKLOCK";

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    address owner;

    // create ciphertexts
    // e.g., 3 ether - 3000000000000000000 wei
    TypesLib.Ciphertext sealedBidBidder1 = TypesLib.Ciphertext({
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
    bytes signatureBidder1 =
        hex"02b3b2fa2c402d59e22a2f141e32a092603862a06a695cbfb574c440372a72cd0636ba8092f304e7701ae9abe910cb474edf0408d9dd78ea7f6f97b7f2464711";
    bytes decryptionKeyBidder1 = hex"7ec49d8f06b34d8d6b2e060ea41652f25b1325fafb041bba9cf24f094fbca259";

    function setUp() public {
        owner = vm.addr(1);

        vm.startPrank(owner);

        SignatureSchemeAddressProvider sigAddrProvider = new SignatureSchemeAddressProvider(owner);
        BlocklockSignatureScheme tlockScheme = new BlocklockSignatureScheme();
        sigAddrProvider.updateSignatureScheme(SCHEME_ID, address(tlockScheme));

        BLS.PointG2 memory pk = BLS.PointG2({
            x: [
                17445541620214498517833872661220947475697073327136585274784354247720096233162,
                18268991875563357240413244408004758684187086817233527689475815128036446189503
            ],
            y: [
                11401601170172090472795479479864222172123705188644469125048759621824127399516,
                8044854403167346152897273335539146380878155193886184396711544300199836788154
            ]
        });
        sigSender = new SignatureSender(pk.x, pk.y, owner, address(sigAddrProvider));

        // deploy implementation contracts for decryption and blocklock senders
        DecryptionSender decryptionSenderImplementationV1 = new DecryptionSender();
        BlocklockSender blocklockSenderImplementationV1 = new BlocklockSender();

        // deploy proxy contracts and point them to their implementation contracts
        decryptionSenderProxy = new UUPSProxy(address(decryptionSenderImplementationV1), "");
        console.log("Decryption Sender proxy contract deployed at: ", address(decryptionSenderProxy));

        blocklockSenderProxy = new UUPSProxy(address(blocklockSenderImplementationV1), "");
        console.log("Blocklock Sender proxy contract deployed at: ", address(blocklockSenderProxy));

        // wrap proxy address in implementation ABI to support delegate calls
        decryptionSender = DecryptionSender(address(decryptionSenderProxy));
        tlock = BlocklockSender(address(blocklockSenderProxy));

        // initialize the contracts
        decryptionSender.initialize(pk.x, pk.y, owner, address(sigAddrProvider));
        tlock.initialize(owner, address(decryptionSender));

        vm.stopPrank();
    }

    function test_DeploymentConfigurations() public view {
        assertTrue(decryptionSender.hasRole(ADMIN_ROLE, owner));
        assert(address(tlock) != address(0));
        assert(address(decryptionSender) != address(0));
        assert(address(sigSender) != address(0));
    }
}
