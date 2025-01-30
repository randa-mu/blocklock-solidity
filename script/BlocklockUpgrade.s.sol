// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

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

contract BlocklockUpgradeScript is Script {
    BlocklockSignatureScheme blocklockSignatureScheme;
    SignatureSchemeAddressProvider signatureSchemeAddressProvider;

    UUPSProxy decryptionSenderProxy;
    DecryptionSender decryptionSenderImplementation;
    DecryptionSender decryptionSenderInstance;

    UUPSProxy blocklockSenderProxy;
    BlocklockSender blocklockSenderImplementation;
    BlocklockSender blocklockSenderInstance;

    MockBlocklockReceiver mockBlocklockReceiver;

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
        address decryptionSenderProxyAddr = 0x9297Bb1d423ef7386C8b2e6B7BdE377977FBedd3;
        address blocklockSenderProxyAddr = 0xfF66908E1d7d23ff62791505b2eC120128918F44;

        decryptionSenderImplementation = new DecryptionSender();
        console.log("\nDecryptionSender implementation contract deployed at: ", address(decryptionSenderImplementation));

        decryptionSenderProxy = UUPSProxy(payable(decryptionSenderProxyAddr));
        console.log("DecryptionSender proxy contract deployed at: ", address(decryptionSenderProxy));

        blocklockSenderImplementation = new BlocklockSender();
        console.log("\nBlocklockSender implementation contract deployed at: ", address(blocklockSenderImplementation));

        blocklockSenderProxy = UUPSProxy(payable(blocklockSenderProxyAddr));
        console.log("BlocklockSender proxy contract deployed at: ", address(blocklockSenderProxy));

        decryptionSenderInstance = DecryptionSender(address(decryptionSenderProxy));
        blocklockSenderInstance = BlocklockSender(address(blocklockSenderProxy));

        console.log("\nDecryptionSender version pre upgrade: ", decryptionSenderInstance.version());
        console.log("BlocklockSender version pre upgrade: ", blocklockSenderInstance.version());

        // Perform implementation contract upgrades
        decryptionSenderInstance.upgradeToAndCall(address(decryptionSenderImplementation), "");
        blocklockSenderInstance.upgradeToAndCall(address(blocklockSenderImplementation), "");

        console.log("\nDecryptionSender version post upgrade: ", decryptionSenderInstance.version());
        console.log("BlocklockSender version post upgrade: ", blocklockSenderInstance.version());

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
 * forge script script/BlocklockUpgrade.s.sol:BlocklockUpgradeScript --rpc-url $CALIBRATIONNET_RPC_URL --broadcast -g 100000 -vvvv
 *
 * -g is the gas limit passed in order to prevent a common error with deploying contracts to the FEVM as per the docs in the filecoin fevm foundry kit here - https://github.com/filecoin-project/fevm-foundry-kit/tree/main
 *
 * For ethereum, add --verify with etherscan key in .env and foundry.toml files
 */
