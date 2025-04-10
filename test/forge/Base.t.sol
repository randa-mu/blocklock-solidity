// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";

abstract contract Base is Test {
    address alice;
    address bob;

    function setUp() public virtual {
        alice = vm.makeAddr("alice");
        bob = vm.makeAddr("bob");

        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
    }

    function signers() internal view returns (address[] memory) {
        address[] memory _signers = new address[](2);
        _signers[0] = alice;
        _signers[1] = bob;
        _signers = sortAccounts(_signers);
        return _signers;
    }

    function sortAccounts(address[] memory accounts) internal pure returns (address[] memory) {
        for (uint256 i = 0; i < accounts.length; i++) {
            for (uint256 j = i + 1; j < accounts.length; j++) {
                if (accounts[i] > accounts[j]) {
                    address tmp = accounts[i];
                    accounts[i] = accounts[j];
                    accounts[j] = tmp;
                }
            }
        }
        return accounts;
    }
}
