// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {Constants} from "../libraries/Constants.sol";

import {JsonUtils} from "../utils/JsonUtils.sol";
import {EnvReader} from "../utils/EnvReader.sol";

import {BlocklockSignatureScheme} from "src/signature-schemes/BlocklockSignatureScheme.sol";
import {SignatureSchemeAddressProvider} from "src/signature-schemes/SignatureSchemeAddressProvider.sol";
import {Factory} from "src/factory/Factory.sol";

/// @title DeploySignatureSchemeAddressProvider
/// @author Randamu
/// @dev Script for deploying BlocklockSignatureScheme contract.
contract DeployBlocklockSignatureScheme is JsonUtils, EnvReader {
    function run() public virtual {
        deployBlocklockSignatureScheme();
    }

    function deployBlocklockSignatureScheme() internal returns (BlocklockSignatureScheme blocklockSignatureScheme) {
        bytes memory code = abi.encodePacked(
            type(BlocklockSignatureScheme).creationCode, abi.encode(getBLSPublicKey().x, getBLSPublicKey().y)
        );

        vm.broadcast();
        address contractAddress;
        if (vm.envBool("USE_RANDAMU_FACTORY")) {
            contractAddress = Factory(vm.envAddress("RANDAMU_CREATE2_FACTORY_CONTRACT_ADDRESS")).deploy(Constants.SALT, code);

            blocklockSignatureScheme = BlocklockSignatureScheme(contractAddress);
        } else {
            blocklockSignatureScheme =
                new BlocklockSignatureScheme{salt: Constants.SALT}(getBLSPublicKey().x, getBLSPublicKey().y);
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
