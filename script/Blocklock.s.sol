// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {MockBlocklockReceiver} from "../src/mocks/MockBlocklockReceiver.sol";
import {SignatureSchemeAddressProvider} from "../src/signature-schemes/SignatureSchemeAddressProvider.sol";
import {BlocklockSignatureScheme} from "../src/blocklock/BlocklockSignatureScheme.sol";
import {SignatureSender} from "../src/signature-requests/SignatureSender.sol";
import {BlocklockSender} from "../src/blocklock/BlocklockSender.sol";
import {DecryptionSender} from "../src/decryption-requests/DecryptionSender.sol";
import {BLS} from "../src/libraries/BLS.sol";
import {TypesLib} from "../src/libraries/TypesLib.sol";
import {UUPSProxy} from "../src/proxy/UUPSProxy.sol";

contract BlocklockScript is Script {
    string SCHEME_ID = "BN254-BLS-BLOCKLOCK";

    BLS.PointG2 pk = BLS.PointG2({
        x: [
            17445541620214498517833872661220947475697073327136585274784354247720096233162,
            18268991875563357240413244408004758684187086817233527689475815128036446189503
        ],
        y: [
            11401601170172090472795479479864222172123705188644469125048759621824127399516,
            8044854403167346152897273335539146380878155193886184396711544300199836788154
        ]
    });

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        address admin = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;

        SignatureSchemeAddressProvider signatureSchemeAddressProvider = new SignatureSchemeAddressProvider(admin);
        BlocklockSignatureScheme blocklockSignatureScheme = new BlocklockSignatureScheme();
        signatureSchemeAddressProvider.updateSignatureScheme(SCHEME_ID, address(blocklockSignatureScheme));

        console.log("\nSignatureSchemeAddressProvider contract deployed to: ", address(signatureSchemeAddressProvider));

        console.log("BlocklockSignatureScheme contract deployed to: ", address(blocklockSignatureScheme));

        DecryptionSender decryptionSenderImplementation = new DecryptionSender();
        console.log("\nDecryptionSender implementation contract deployed at: ", address(decryptionSenderImplementation));

        UUPSProxy decryptionSenderProxy = new UUPSProxy(address(decryptionSenderImplementation), "");
        console.log("DecryptionSender proxy contract deployed at: ", address(decryptionSenderProxy));

        BlocklockSender blocklockSenderImplementation = new BlocklockSender();
        console.log("\nBlocklockSender implementation contract deployed at: ", address(blocklockSenderImplementation));

        UUPSProxy blocklockSenderProxy = new UUPSProxy(address(blocklockSenderImplementation), "");
        console.log("BlocklockSender proxy contract deployed at: ", address(blocklockSenderProxy));

        DecryptionSender decryptionSender = DecryptionSender(address(decryptionSenderProxy));
        BlocklockSender blocklockSender = BlocklockSender(address(blocklockSenderProxy));

        decryptionSender.initialize(pk.x, pk.y, admin, address(signatureSchemeAddressProvider));
        blocklockSender.initialize(admin, address(decryptionSenderProxy));

        MockBlocklockReceiver mockBlocklockReceiver = new MockBlocklockReceiver(address(blocklockSenderProxy));
        console.log("\nMockBlocklockReceiver deployed at: ", address(mockBlocklockReceiver));

        vm.stopBroadcast();
    }
}

/**
 * # Deployment steps
 *
 * ## STEP 1. Load the variables in the .env file
 * source .env
 *
 * ## STEP 2. Deploy and verify the contract
 * forge script script/Blocklock.s.sol:BlocklockScript --rpc-url $CALIBRATIONNET_RPC_URL --broadcast -g 100000 -vvvv
 *
 * -g is the gas limit passed in order to prevent a common error with deploying contracts to the FEVM as per the docs in the filecoin fevm foundry kit here - https://github.com/filecoin-project/fevm-foundry-kit/tree/main
 *
 * For ethereum, add --verify with etherscan key in .env and foundry.toml files
 */
