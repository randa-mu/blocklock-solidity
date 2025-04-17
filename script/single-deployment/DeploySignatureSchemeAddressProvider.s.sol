// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {Constants} from "../libraries/Constants.sol";

import {JsonUtils} from "../utils/JsonUtils.sol";
import {EnvReader} from "../utils/EnvReader.sol";

import {SignatureSchemeAddressProvider} from "src/signature-schemes/SignatureSchemeAddressProvider.sol";
import {Factory} from "src/factory/Factory.sol";

/// @title DeploySignatureSchemeAddressProvider
/// @dev Script for deploying SignatureSchemeAddressProvider contract.
contract DeploySignatureSchemeAddressProvider is JsonUtils, EnvReader {
    function run() public virtual {
        deploySignatureSchemeAddressProvider();
    }

    function deploySignatureSchemeAddressProvider()
        internal
        returns (SignatureSchemeAddressProvider signatureSchemeAddressProvider)
    {
        bytes memory code =
            abi.encodePacked(type(SignatureSchemeAddressProvider).creationCode, abi.encode(getSignerAddress()));

        vm.broadcast();
        address contractAddress;
        if (vm.envBool("USE_RANDAMU_FACTORY")) {
            contractAddress = Factory(vm.envAddress("RANDAMU_CREATE2_FACTORY_CONTRACT_ADDRESS")).deploy(Constants.SALT, code);

            signatureSchemeAddressProvider = SignatureSchemeAddressProvider(contractAddress);
        } else {
            signatureSchemeAddressProvider =
                new SignatureSchemeAddressProvider{salt: Constants.SALT}(getSignerAddress());
            contractAddress = address(signatureSchemeAddressProvider);
        }

        _writeAddressToJsonInput(
            Constants.DEPLOYMENT_INPUT_JSON_PATH, "signatureSchemeAddressProviderAddress", contractAddress
        );

        console.log("SignatureSchemeAddressProvider contract deployed at: ", contractAddress);
    }
}
