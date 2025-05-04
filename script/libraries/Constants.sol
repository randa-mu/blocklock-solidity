// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

library Constants {
    bytes32 constant SALT = bytes32(uint256(119));

    string constant BLOCKLOCK_BN254_SIGNATURE_SCHEME_ID = "BN254-BLS-BLOCKLOCK";
    string constant DEPLOYMENT_INPUT_JSON_PATH = "Deployment_input.json";
}
