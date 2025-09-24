// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

/// @title BlocklockErrors library
/// @notice Centralized custom errors for BlocklockSender contract
library BlocklockErrors {
    error GrantRoleFailed();
    error DirectFundingRequired();
    error NoRequestFound();
    error InvalidPremiumPercentage();
    error InvalidRequestId();
    error CallbackGasLimitTooHigh();
    error NoActiveSubscription();
    error FeeTooLow();
    error InvalidDecryptionKeyLength();
    error UnsupportedMessageLength();
    error InvalidDecryptionKeyOrCiphertext();
    error ContractNotConfigured();
    error ContractDisabled();
}
