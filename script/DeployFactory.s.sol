// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {Factory} from "src/factory/Factory.sol";

/// @title DeployFactory
/// @dev Script for deploying CREATE2 Factory contract.
contract DeployFactory is Script {
    function run() public virtual {
        deployCREATE2Factory();
    }

    function deployCREATE2Factory() internal {
        vm.broadcast();
        Factory create2Factory = new Factory();

        console.log("CREATE2 Factory deployed at: ", address(create2Factory));
    }
}
