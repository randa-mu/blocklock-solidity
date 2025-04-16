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
        uint256 chainHeight;
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
                    14142380308423906610328325205633754694002301558654408701934220147059967542660,
                    4795984740938726483924720262587026838890051381570343702421443260575124596446
                ],
                y: [
                    13301122453285478420056122708237526083484415709254283392885579853639158169617,
                    11125759247493978573666410429063118092803139083876927879642973106997490249635
                ]
            }),
            v: hex"63f745f4240f4708db37b0fa0e40309a37ab1a65f9b1be4ac716a347d4fe57fe",
            w: hex"e8aadd66a9a67c00f134b1127b7ef85046308c340f2bb7cee431bd7bfe950bd4"
        });

        bytes memory signature =
            hex"02b3b2fa2c402d59e22a2f141e32a092603862a06a695cbfb574c440372a72cd0636ba8092f304e7701ae9abe910cb474edf0408d9dd78ea7f6f97b7f2464711";

        bytes memory decryptionKey = hex"7ec49d8f06b34d8d6b2e060ea41652f25b1325fafb041bba9cf24f094fbca259";

        ciphertextDataUint[plaintext] = CiphertextDataUint({
            plaintext: plaintext,
            chainHeight: 13,
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
