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
}
