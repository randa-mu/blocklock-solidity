// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {Constants} from "../libraries/Constants.sol";

import {JsonUtils} from "../utils/JsonUtils.sol";

import {MockBlocklockReceiver} from "src/mocks/MockBlocklockReceiver.sol";
import {Factory} from "src/factory/Factory.sol";

/// @title DeploySignatureSchemeAddressProvider
/// @author Randamu
/// @dev Script for deploying MockBlocklockReceiver contract.
contract DeployBlocklockReceiver is JsonUtils {
    function run() public virtual {
        address blocklockSenderAddress =
            _readAddressFromJsonInput(Constants.DEPLOYMENT_INPUT_JSON_PATH, "blocklockSenderProxyAddress");

        deployBlocklockReceiver(blocklockSenderAddress);
    }

    function deployBlocklockReceiver(address blocklockSenderAddress)
        internal
        returns (MockBlocklockReceiver mockBlocklockReceiver)
    {
        bytes memory code =
            abi.encodePacked(type(MockBlocklockReceiver).creationCode, abi.encode(blocklockSenderAddress));

        vm.broadcast();
        address contractAddress = Factory(Constants.CREATE2_FACTORY).deploy(Constants.SALT, code);

        mockBlocklockReceiver = MockBlocklockReceiver(contractAddress);

        console.log("MockBlocklockReceiver deployed at: ", contractAddress);
    }
}
