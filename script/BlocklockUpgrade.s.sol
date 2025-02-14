// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {BlocklockSender} from "../src/blocklock/BlocklockSender.sol";
import {DecryptionSender} from "../src/decryption-requests/DecryptionSender.sol";
import {BLS} from "../src/libraries/BLS.sol";
import {TypesLib} from "../src/libraries/TypesLib.sol";
import {UUPSProxy} from "../src/proxy/UUPSProxy.sol";

contract BlocklockUpgradeScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        address decryptionSenderProxyAddr = 0x9297Bb1d423ef7386C8b2e6B7BdE377977FBedd3;
        address blocklockSenderProxyAddr = 0xfF66908E1d7d23ff62791505b2eC120128918F44;

        DecryptionSender decryptionSenderImplementation = new DecryptionSender();
        console.log("\nDecryptionSender implementation contract deployed at: ", address(decryptionSenderImplementation));

        UUPSProxy decryptionSenderProxy = UUPSProxy(payable(decryptionSenderProxyAddr));
        console.log("DecryptionSender proxy contract deployed at: ", address(decryptionSenderProxy));

        BlocklockSender blocklockSenderImplementation = new BlocklockSender();
        console.log("\nBlocklockSender implementation contract deployed at: ", address(blocklockSenderImplementation));

        UUPSProxy blocklockSenderProxy = UUPSProxy(payable(blocklockSenderProxyAddr));
        console.log("BlocklockSender proxy contract deployed at: ", address(blocklockSenderProxy));

        DecryptionSender decryptionSender = DecryptionSender(address(decryptionSenderProxy));
        BlocklockSender blocklockSender = BlocklockSender(address(blocklockSenderProxy));

        console.log("\nDecryptionSender version pre upgrade: ", decryptionSender.version());
        console.log("BlocklockSender version pre upgrade: ", blocklockSender.version());

        // Perform implementation contract upgrades
        decryptionSender.upgradeToAndCall(address(decryptionSenderImplementation), "");
        blocklockSender.upgradeToAndCall(address(blocklockSenderImplementation), "");

        console.log("\nDecryptionSender version post upgrade: ", decryptionSender.version());
        console.log("BlocklockSender version post upgrade: ", blocklockSender.version());

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
