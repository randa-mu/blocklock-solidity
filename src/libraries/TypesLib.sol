// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import "./BLS.sol";

/// @title TypesLib
/// @author Randamu
/// @notice Library declaring custom data types used for randomness and blocklock requests
library TypesLib {
    /// @notice  Ciphertext representing data encrypted off-chain
    struct Ciphertext {
        BLS.PointG2 u;
        bytes v;
        bytes w;
    }

    /// @notice  Blocklock request stores details needed to generate blocklock decryption keys
    struct BlocklockRequest {
        uint256 subId; // 0 for direct funding
        uint256 directFundingPayment; // > 0 for direct funding or if subId == 0
        uint64 decryptionRequestID;
        uint256 blockHeight;
        Ciphertext ciphertext;
        bytes signature;
        bytes decryptionKey;
        address callback;
    }

    /// @notice  Decryption request stores details for each decryption request
    struct DecryptionRequest {
        string schemeID; // signature scheme id, e.g., "BN254", "BLS12-381", "TESS"
        bytes ciphertext;
        bytes condition;
        bytes decryptionKey;
        bytes signature;
        address callback;
        // used by offchain agent / oracle for callback gasLimit
        // should cover costs for callbacks from decryptionSender to consumer contract via blocklockSender
        uint32 callbackGasLimit;
        bool isFulfilled;
    }
}
