// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";

/// @title Base test contract
/// @dev Provides core functionalities needed by all other tests.
abstract contract Base is Test {
    address internal admin;
    address internal alice;
    address internal bob;

    function setUp() public virtual {
        admin = makeAddr("admin");
        alice = makeAddr("alice");
        bob = makeAddr("bob");

        vm.deal(admin, 10 ether);
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
    }

    function signers() internal view returns (address[] memory) {
        address[] memory _signers = new address[](2);
        _signers[0] = admin;
        _signers[1] = alice;
        _signers[2] = bob;
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
