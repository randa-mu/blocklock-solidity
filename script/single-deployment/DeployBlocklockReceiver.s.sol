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
        address contractAddress;
        if (vm.envBool("USE_RANDAMU_FACTORY")) {
            contractAddress = Factory(vm.envAddress("RANDAMU_CREATE2_FACTORY_CONTRACT_ADDRESS")).deploy(Constants.SALT, code);

            mockBlocklockReceiver = MockBlocklockReceiver(payable(contractAddress));
        } else {
            mockBlocklockReceiver = new MockBlocklockReceiver{salt: Constants.SALT}(blocklockSenderAddress);
            contractAddress = address(mockBlocklockReceiver);
        }

        console.log("MockBlocklockReceiver deployed at: ", contractAddress);
    }
}
