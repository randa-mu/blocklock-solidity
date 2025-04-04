// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import "./BLS.sol";

library TypesLib {
    // Signature request struct for signature request type
    struct SignatureRequest {
        bytes message; // plaintext message to hash and sign
        bytes messageHash; // hashed message to sign
        bytes condition; // optional condition, length can be zero for immediate message signing
        string schemeID; // signature scheme id, e.g., "BN254", "BLS12-381", "TESS"
        address callback; // the requester address to call back. Must implement ISignatureReceiver interface to support the required callback
    }

    // Blocklock request stores details needed to generate blocklock decryption keys
    struct BlocklockRequest {
        uint256 decryptionRequestID;
        uint256 blockHeight;
        Ciphertext ciphertext;
        bytes signature;
        bytes decryptionKey;
        address callback;
    }

    struct Ciphertext {
        BLS.PointG2 u;
        bytes v;
        bytes w;
    }

    // Decryption request stores details for each decryption request
    struct DecryptionRequest {
        string schemeID; // signature scheme id, e.g., "BN254", "BLS12-381", "TESS"
        bytes ciphertext;
        bytes condition;
        bytes decryptionKey;
        bytes signature;
        address callback;
        bool isFulfilled;
    }

    // fixme replace existing structs in blocklockSender and decryptionSender
    struct BlocklockRequestV2 {
        uint256 subId; // new // 0 for direct funding
        uint256 directFundingPayment; // new // > 0 for direct funding or if subId == 0
        uint256 decryptionRequestID;
        uint256 blockHeight;
        Ciphertext ciphertext;
        bytes signature;
        bytes decryptionKey;
        address callback;
    }

    struct DecryptionRequestV2 {
        string schemeID; // signature scheme id, e.g., "BN254", "BLS12-381", "TESS"
        bytes ciphertext;
        bytes condition;
        bytes decryptionKey;
        bytes signature;
        address callback;
        uint32 callbackGasLimit; // new // fixme use in offchain agent / oracle for callback gasLimit
        bool isFulfilled;
    }
}
