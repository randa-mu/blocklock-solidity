// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {Constants} from "../libraries/Constants.sol";

import {JsonUtils} from "../utils/JsonUtils.sol";

import {BlocklockSender} from "src/blocklock/BlocklockSender.sol";
import {UUPSProxy} from "src/proxy/UUPSProxy.sol";
import {Factory} from "src/factory/Factory.sol";

/// @title DeployBlocklockSender
/// @author Randamu
/// @dev Script for deploying or upgrading the BlocklockSender contract.
/// Reads an environment variable to determine if it's an upgrade (new implementation only) or a full deployment.
contract DeployBlocklockSender is JsonUtils {
    /// @notice Runs the deployment script, checking the environment variable to determine whether to upgrade or deploy.
    function run() public virtual {
        bool isUpgrade = vm.envBool("IS_UPGRADE");
        address decryptionSenderProxyAddress =
            _readAddressFromJsonInput(Constants.DEPLOYMENT_INPUT_JSON_PATH, "decryptionSenderProxyAddress");
        deployBlocklockSenderProxy(decryptionSenderProxyAddress, isUpgrade);
    }

    /// @notice Deploys the BlocklockSender proxy contract or upgrades its implementation.
    /// @param decryptionSenderProxyAddress The address of the DecryptionSender proxy contract.
    /// @param isUpgrade A flag indicating whether to perform an upgrade (true) or a full deployment (false).
    function deployBlocklockSenderProxy(address decryptionSenderProxyAddress, bool isUpgrade)
        internal
        returns (BlocklockSender blocklockSenderInstance)
    {
        address implementation = deployBlocklockSenderImplementation();

        if (isUpgrade) {
            vm.broadcast();
            address proxyAddress =
                _readAddressFromJsonInput(Constants.DEPLOYMENT_INPUT_JSON_PATH, "blocklockSenderProxyAddress");

            BlocklockSender(proxyAddress).upgradeToAndCall(implementation, "");
            console.log("BlocklockSender contract upgraded to new implementation at: ", implementation);
            blocklockSenderInstance = BlocklockSender(proxyAddress);
        } else {
            // Deploy a new proxy if it's a full deployment
            bytes memory code = abi.encodePacked(type(UUPSProxy).creationCode, abi.encode(implementation, ""));

            vm.broadcast();
            address contractAddress = Factory(Constants.CREATE2_FACTORY).deploy(Constants.SALT, code);

            blocklockSenderInstance = BlocklockSender(contractAddress);

            _writeAddressToJsonInput(
                Constants.DEPLOYMENT_INPUT_JSON_PATH, "blocklockSenderProxyAddress", contractAddress
            );

            vm.broadcast();
            blocklockSenderInstance.initialize(Constants.ADMIN, decryptionSenderProxyAddress);

            console.log("BlocklockSender proxy contract deployed at: ", contractAddress);
        }
    }

    /// @notice Deploys the BlocklockSender implementation contract.
    /// @return implementation The address of the newly deployed implementation contract.
    function deployBlocklockSenderImplementation() internal returns (address implementation) {
        bytes memory code = type(BlocklockSender).creationCode;

        vm.broadcast();
        implementation = Factory(Constants.CREATE2_FACTORY).deploy(Constants.SALT, code);

        console.log("BlocklockSender implementation contract deployed at: ", implementation);
    }
}
