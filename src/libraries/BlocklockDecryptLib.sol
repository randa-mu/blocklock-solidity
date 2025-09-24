// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {TypesLib} from "./TypesLib.sol";
import {BlocklockCryptoLib} from "../blocklock/BlocklockCryptoLib.sol";

/// @title BlocklockDecryptLib
/// @notice External library for blocklock decryption functionality
library BlocklockDecryptLib {
    /// @notice Decrypts a ciphertext into plaintext using a decryption key
    function decrypt(
        TypesLib.Ciphertext calldata ciphertext,
        bytes calldata decryptionKey,
        bytes memory DST_H3,
        bytes memory DST_H4
    ) external view returns (bytes memory) {
        return BlocklockCryptoLib.decrypt(ciphertext, decryptionKey, DST_H3, DST_H4);
    }
}
