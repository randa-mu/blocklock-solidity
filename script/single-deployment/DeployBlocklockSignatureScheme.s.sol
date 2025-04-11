// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {Constants} from "../libraries/Constants.sol";

import {JsonUtils} from "../utils/JsonUtils.sol";
import {SignatureUtils} from "../utils/SignatureUtils.sol";

import {BlocklockSignatureScheme} from "src/signature-schemes/BlocklockSignatureScheme.sol";
import {SignatureSchemeAddressProvider} from "src/signature-schemes/SignatureSchemeAddressProvider.sol";
import {Factory} from "src/factory/Factory.sol";

/// @title DeploySignatureSchemeAddressProvider
/// @author Randamu
/// @dev Script for deploying BlocklockSignatureScheme contract.
contract DeployBlocklockSignatureScheme is JsonUtils, SignatureUtils {
    function run() public virtual {
        deployBlocklockSignatureScheme();
    }

    function deployBlocklockSignatureScheme() internal returns (BlocklockSignatureScheme blocklockSignatureScheme) {
        bytes memory code = abi.encodePacked(
            type(BlocklockSignatureScheme).creationCode, abi.encode(BLS_PUBLIC_KEY.x, BLS_PUBLIC_KEY.y)
        );

        vm.broadcast();
        address contractAddress;
        if (Constants.USE_RANDAMU_FACTORY) {
            contractAddress = Factory(Constants.CREATE2_FACTORY).deploy(Constants.SALT, code);

            blocklockSignatureScheme = BlocklockSignatureScheme(contractAddress);
        } else {
            blocklockSignatureScheme =
                new BlocklockSignatureScheme{salt: Constants.SALT}(BLS_PUBLIC_KEY.x, BLS_PUBLIC_KEY.y);
            contractAddress = address(blocklockSignatureScheme);
        }

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
