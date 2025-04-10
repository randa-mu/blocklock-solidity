// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {Constants} from "../libraries/Constants.sol";

import {JsonUtils} from "../utils/JsonUtils.sol";

import {DecryptionSender} from "src/decryption-requests/DecryptionSender.sol";
import {UUPSProxy} from "src/proxy/UUPSProxy.sol";
import {Factory} from "src/factory/Factory.sol";

/// @title DeployDecryptionSender
/// @author Randamu
/// @dev Script for deploying or upgrading the DecryptionSender contract.
/// Reads an environment variable to determine if it's an upgrade (new implementation only) or a full deployment.
contract DeployDecryptionSender is JsonUtils {
    /// @notice Runs the deployment script, checking the environment variable to determine whether to upgrade or deploy.
    function run() public virtual {
        bool isUpgrade = vm.envBool("IS_UPGRADE");
        address signatureSchemeAddressProvider =
            _readAddressFromJsonInput(Constants.DEPLOYMENT_INPUT_JSON_PATH, "signatureSchemeAddressProviderAddress");
        deployDecryptionSenderProxy(signatureSchemeAddressProvider, isUpgrade);
    }

    /// @notice Deploys the DecryptionSender proxy contract or upgrades its implementation.
    /// @param signatureSchemeAddressesProviderAddress The address of the SignatureSchemeAddressesProvider contract.
    /// @param isUpgrade A flag indicating whether to perform an upgrade (true) or a full deployment (false).
    function deployDecryptionSenderProxy(address signatureSchemeAddressesProviderAddress, bool isUpgrade)
        internal
        returns (DecryptionSender decryptionSenderInstance)
    {
        address implementation = deployDecryptionSenderImplementation();

        if (isUpgrade) {
            vm.broadcast();
            address proxyAddress =
                _readAddressFromJsonInput(Constants.DEPLOYMENT_INPUT_JSON_PATH, "decryptionSenderProxyAddress");
            DecryptionSender(proxyAddress).upgradeToAndCall(implementation, "");
            console.log("DecryptionSender contract upgraded to new implementation at: ", implementation);
            decryptionSenderInstance = DecryptionSender(proxyAddress);
        } else {
            // Deploy a new proxy if it's a full deployment
            bytes memory code = abi.encodePacked(type(UUPSProxy).creationCode, abi.encode(implementation, ""));

            vm.broadcast();
            address contractAddress = Factory(Constants.CREATE2_FACTORY).deploy(Constants.SALT, code);

            decryptionSenderInstance = DecryptionSender(contractAddress);

            _writeAddressToJsonInput(
                Constants.DEPLOYMENT_INPUT_JSON_PATH, "decryptionSenderProxyAddress", contractAddress
            );

            vm.broadcast();
            decryptionSenderInstance.initialize(Constants.ADMIN, signatureSchemeAddressesProviderAddress);

            console.log("DecryptionSender proxy contract deployed at: ", contractAddress);
        }
    }

    /// @notice Deploys the DecryptionSender implementation contract.
    /// @return implementation The address of the newly deployed implementation contract.
    function deployDecryptionSenderImplementation() internal returns (address implementation) {
        bytes memory code = type(DecryptionSender).creationCode;

        vm.broadcast();
        implementation = Factory(Constants.CREATE2_FACTORY).deploy(Constants.SALT, code);

        console.log("DecryptionSender implementation contract deployed at: ", implementation);
    }
}
