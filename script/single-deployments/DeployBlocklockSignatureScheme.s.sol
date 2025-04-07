// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {Constants} from "../libraries/Constants.sol";

import {JsonUtils} from "../utils/JsonUtils.sol";

import {BlocklockSignatureScheme} from "src/signature-schemes/BlocklockSignatureScheme.sol";
import {SignatureSchemeAddressProvider} from "src/signature-schemes/SignatureSchemeAddressProvider.sol";
import {Factory} from "src/factory/Factory.sol";

/// @title DeploySignatureSchemeAddressProvider
/// @dev Script for deploying BlocklockSignatureScheme contract.
contract DeployBlocklockSignatureScheme is JsonUtils {
    function run() public virtual {
        deployBlocklockSignatureScheme();
    }

    function deployBlocklockSignatureScheme() internal returns (BlocklockSignatureScheme blocklockSignatureScheme) {
        bytes memory code = type(BlocklockSignatureScheme).creationCode;

        vm.broadcast();
        address contractAddress = Factory(Constants.CREATE2_FACTORY).deploy(Constants.SALT, code);

        blocklockSignatureScheme = BlocklockSignatureScheme(contractAddress);

        console.log("BlocklockSignatureScheme contract deployed to: ", contractAddress);

        address signatureSchemeAddressProviderAddress =
            _readAddressFromJsonInput(Constants.DEPLOYMENT_INPUT_JSON_PATH, "signatureSchemeAddressProviderAddress");
        SignatureSchemeAddressProvider signatureSchemeAddressProvider =
            SignatureSchemeAddressProvider(signatureSchemeAddressProviderAddress);

        vm.broadcast();
        signatureSchemeAddressProvider.updateSignatureScheme(
            Constants.BLOCKLOCK_BN254_SIGNATURE_SCHEME_ID, contractAddress
        );
    }
}
