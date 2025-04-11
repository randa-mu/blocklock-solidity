// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

library Constants {
    address constant CREATE2_FACTORY = 0x700b6A60ce7EaaEA56F065753d8dcB9653dbAD35;

    bytes32 constant SALT = bytes32(uint256(100));

    string constant BLOCKLOCK_BN254_SIGNATURE_SCHEME_ID = "BN254-BLS-BLOCKLOCK";
    string constant DEPLOYMENT_INPUT_JSON_PATH = "Deployment_input.json";

    bool constant USE_RANDAMU_FACTORY = false;
}
