// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {Script} from "forge-std/Script.sol";

contract JsonUtils is Script {
    function _readAddressFromJsonInput(string memory fileName, string memory contractName)
        internal
        view
        returns (address)
    {
        string memory path = _constructJsonFilePath(fileName);
        string memory json = vm.readFile(path);

        string memory jsonKey = string.concat(".", contractName);
        return vm.parseJsonAddress(json, jsonKey);
    }

    function _writeAddressToJsonInput(string memory path, string memory jsonKey, address contractAddress) internal {
        string memory obj = "deployment addresses input";
        string memory output = vm.serializeAddress(obj, jsonKey, contractAddress);
        vm.writeJson(output, _constructJsonFilePath(path));
    }

    function _readJsonFile(string memory _jsonFile) internal view returns (string memory) {
        return vm.readFile(_constructJsonFilePath(_jsonFile));
    }

    function _constructJsonFilePath(string memory _jsonFile) internal view returns (string memory) {
        string memory root = vm.projectRoot();
        return string.concat(root, "/script/json/", _jsonFile);
    }
}
