// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {Script} from "forge-std/Script.sol";

import {BLS} from "src/libraries/BLS.sol";

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

    function getBLSPublicKey() internal view returns (BLS.PointG2 memory BLS_PUBLIC_KEY) {
        BLS_PUBLIC_KEY = BLS.PointG2({
            x: [vm.envUint("BLS_PUBLIC_KEY_X0"), vm.envUint("BLS_PUBLIC_KEY_X1")],
            y: [vm.envUint("BLS_PUBLIC_KEY_Y0"), vm.envUint("BLS_PUBLIC_KEY_Y1")]
        });
    }
}
