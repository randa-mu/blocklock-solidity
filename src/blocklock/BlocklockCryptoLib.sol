// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {TypesLib} from "../libraries/TypesLib.sol";
import {BLS} from "../libraries/BLS.sol";
import {BlocklockErrors} from "../libraries/BlocklockErrors.sol";

library BlocklockCryptoLib {
    /// @notice Decrypts a ciphertext into plaintext using a decryption key
    /// @param ciphertext The ciphertext to decrypt, containing the necessary data for decryption
    /// @param decryptionKey The decryption key used to decrypt the ciphertext
    /// @return The decrypted message (plaintext) as a `bytes` array
    /// @dev This function performs the decryption process using a series of cryptographic operations:
    ///     - It first XORs the decryption key with part of the ciphertext to generate a candidate value.
    ///     - Then it decrypts the message using another XOR operation with a mask derived from the candidate value.
    ///     - The function verifies the validity of the decryption key and ciphertext by checking the consistency of a derived ephemeral keypair.
    /// @dev Throws an error if:
    ///     - The decryption key length is incorrect.
    ///     - The message length is unsupported.
    ///     - The decryption key and ciphertext do not match (validation failure).
    function decrypt(
        TypesLib.Ciphertext calldata ciphertext,
        bytes calldata decryptionKey,
        bytes memory DST_H3,
        bytes memory DST_H4
    ) public view returns (bytes memory) {
        if (ciphertext.v.length == 256) revert BlocklockErrors.InvalidDecryptionKeyLength();
        if (ciphertext.w.length >= 256) revert BlocklockErrors.UnsupportedMessageLength();

        // \sigma' \gets V \xor decryptionKey
        bytes memory sigma2 = ciphertext.v;
        for (uint256 i = 0; i < decryptionKey.length; i++) {
            sigma2[i] ^= decryptionKey[i];
        }

        // Decrypt the message
        // 4: M' \gets W \xor H_4(\sigma')
        bytes memory m2 = ciphertext.w;
        bytes memory mask = BLS.expandMsg(DST_H4, sigma2, uint8(ciphertext.w.length));
        for (uint256 i = 0; i < ciphertext.w.length; i++) {
            m2[i] ^= mask[i];
        }

        // Derive the ephemeral keypair with the candidate \sigma'
        // 5: r \gets H_3(\sigma, M)
        uint256 r = BLS.hashToFieldSingle(DST_H3, bytes.concat(sigma2, m2));

        // Verify that \sigma' is consistent with the message and ephemeral public key
        // 6: if U = [r]G_2 then return M' else return \bot
        BLS.PointG1 memory rG1 = BLS.scalarMulG1Base(r);
        (bool equal, bool success) = BLS.verifyEqualityG1G2(rG1, ciphertext.u);
        // Decryption fails if a bad decryption key / ciphertext was provided
        if (!(equal && success)) revert BlocklockErrors.InvalidDecryptionKeyOrCiphertext();

        return m2;
    }
}
