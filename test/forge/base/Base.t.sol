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
                    8170104253480136655189303292926596565998324573954843222301178640818583058767,
                    3734667108182226346464699698648987468066959092442871843994743121863149281349
                ],
                y: [
                    11365405476005364849296689146191063620313890468494751033614653278517929462010,
                    15447260375633765501272878130235011006969766368352637843994883527173054707607
                ]
            }),
            v: hex"530131f0f06f06523924c2cf053d140edb615ec69c8588357691bfa5e0a83cfc",
            w: hex"5cddd44e856474b93d85125c77f97ac4e7cbe8771a459e389d3b0d19ea0237c3"
        });

        bytes memory signature =
            hex"02c661272e7cfb65203d192e94a12ff524ac53462f354598e4868ff527ae0aef22c70822487a1c7d12be9365cc2ed9158887a1fd204c60fad152d7d7b51d8944";

        bytes memory decryptionKey = hex"bf7692e46676000933d3a00129eafd80c5fa8a8a424012ac3c373bf6b3a2d8a8";

        ciphertextDataUint[plaintext] = CiphertextDataUint({
            plaintext: plaintext,
            condition: abi.encodePacked("B", uint256(18)), // "B" for chain height or block number condition
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
