// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";

import {TypesLib} from "../../../src/libraries/TypesLib.sol";
import {BLS} from "../../../src/libraries/BLS.sol";

/// @title Base test contract
/// @dev Provides core functionalities needed by all other tests.
abstract contract Base is Test {
    address internal admin;
    address internal alice;
    address internal bob;

    struct CiphertextDataUint {
        uint256 plaintext;
        bytes condition;
        TypesLib.Ciphertext ciphertext;
        bytes signature;
        bytes decryptionKey;
    }

    mapping(uint256 => CiphertextDataUint) internal ciphertextDataUint;

    function setUp() public virtual {
        admin = makeAddr("admin");
        alice = makeAddr("alice");
        bob = makeAddr("bob");

        vm.deal(admin, 10 ether);
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);

        generateMockCiphertextData();
    }

    function generateMockCiphertextData() internal {
        // generate and store ciphertexts and keys

        // 1. 3 ether
        uint256 plaintext = 3 ether;

        TypesLib.Ciphertext memory ciphertext = TypesLib.Ciphertext({
            u: BLS.PointG2({
                x: [
                    15400123135410175383820132114210070294154316822955415832645881020977577238415,
                    9335672780846811668659413216320771384451704387891684161568809056709633441627
                ],
                y: [
                    17465030637995234965729840389913899392948957861509585407647311800836417857964,
                    17217796275830825345990918796120315699217836952192867448758285739983534744010
                ]
            }),
            v: hex"54b744fa0514a42e8e8bf8a23a0c619e059fbc072d1774f5c4d389a218dce7f1",
            w: hex"c0884030be948e1477202760f15f302c56fd9e22e39cb0afb21e9a2140d363d4"
        });

        bytes memory signature =
            hex"06b799aacebcbc3bd533cbd16bf42740be3402a20aec013e252553280df8774428e4c425fbe4c6803c0f58045e9a8dbd875d6c9a3d9b80c584c3481922927fd6";

        bytes memory decryptionKey = hex"948918d64af8e911c98d62c282764bed2488a47797a31e711956a6e87846efa7";

        ciphertextDataUint[plaintext] = CiphertextDataUint({
            plaintext: plaintext,
            condition: abi.encode("B", uint256(18)), // "B" for chain height or block number condition
            ciphertext: ciphertext,
            signature: signature,
            decryptionKey: decryptionKey
        });
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
