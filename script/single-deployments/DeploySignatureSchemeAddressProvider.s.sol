// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {Constants} from "../libraries/Constants.sol";

import {JsonUtils} from "../utils/JsonUtils.sol";

import {SignatureSchemeAddressProvider} from "src/signature-schemes/SignatureSchemeAddressProvider.sol";
import {Factory} from "src/factory/Factory.sol";

/// @title DeploySignatureSchemeAddressProvider
/// @dev Script for deploying SignatureSchemeAddressProvider contract.
contract DeploySignatureSchemeAddressProvider is JsonUtils {
    function run() public virtual {
        deploySignatureSchemeAddressProvider();
    }

    function deploySignatureSchemeAddressProvider()
        internal
        returns (SignatureSchemeAddressProvider signatureSchemeAddressProvider)
    {
        bytes memory code =
            abi.encodePacked(type(SignatureSchemeAddressProvider).creationCode, abi.encode(Constants.ADMIN));

        vm.broadcast();
        address contractAddress = Factory(Constants.CREATE2_FACTORY).deploy(Constants.SALT, code);

        signatureSchemeAddressProvider = SignatureSchemeAddressProvider(contractAddress);

        _writeAddressToJsonInput(
            Constants.DEPLOYMENT_INPUT_JSON_PATH, "signatureSchemeAddressProviderAddress", contractAddress
        );

        console.log("SignatureSchemeAddressProvider contract deployed to: ", contractAddress);
    }
}
