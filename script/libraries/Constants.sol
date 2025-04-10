// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

library Constants {
    address constant ADMIN = 0xa0Ee7A142d267C1f36714E4a8F75612F20a79720;
    address constant CREATE2_FACTORY = 0x700b6A60ce7EaaEA56F065753d8dcB9653dbAD35;

    bytes32 constant SALT = bytes32(uint256(100));

    string constant BLOCKLOCK_BN254_SIGNATURE_SCHEME_ID = "BN254-BLS-BLOCKLOCK"; // for blocklock signatures
    string constant RANDOMNESS_BN254_SIGNATURE_SCHEME_ID = "BN254"; // for randomness signatures
    string constant DEPLOYMENT_INPUT_JSON_PATH = "Deployment_input.json";
}
