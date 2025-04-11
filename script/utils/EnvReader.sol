// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {Script} from "forge-std/Script.sol";

abstract contract EnvReader is Script {
    function addressEnvOrDefault(string memory envName, address defaultAddr) internal view returns (address) {
        try vm.envAddress(envName) returns (address env) {
            return env;
        } catch {
            return defaultAddr;
        }
    }

    function getSignerAddress() internal view returns (address wallet) {
        // Load private key from .env
        uint256 privateKey = vm.envUint("PRIVATE_KEY");

        // Extract the address
        wallet = vm.addr(privateKey);
    }
}
