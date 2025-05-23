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

    /// @notice  BlocklockRequest stores details needed to generate blocklock decryption keys
    struct BlocklockRequest {
        uint256 subId; // must be 0 for direct funding
        uint256 directFundingFeePaid; // must be > 0 for direct funding and if subId == 0
        uint32 callbackGasLimit; // must be between 0 and maxGasLimit
        uint256 decryptionRequestId;
        bytes condition;
        Ciphertext ciphertext;
        bytes signature;
        bytes decryptionKey;
        address callback;
    }

    /// @notice  DecryptionRequest stores details for each decryption request
    struct DecryptionRequest {
        string schemeID;
        bytes ciphertext;
        bytes condition;
        bytes decryptionKey;
        bytes signature;
        address callback;
        bool isFulfilled;
    }
}
