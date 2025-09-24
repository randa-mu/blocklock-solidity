// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {SubscriptionAPI} from "../subscription/SubscriptionAPI.sol";
import {BlocklockErrors} from "./BlocklockErrors.sol";

/// @title BlocklockConfigLib
/// @notice External library for contract configuration management
library BlocklockConfigLib {
    /// @notice Sets contract configuration and validates parameters
    function setConfiguration(
        SubscriptionAPI.Config storage config,
        uint32 maxGasLimit,
        uint32 gasAfterPaymentCalculation,
        uint32 fulfillmentFlatFeeNativePPM,
        uint32 weiPerUnitGas,
        uint32 blsPairingCheckOverhead,
        uint8 nativePremiumPercentage,
        uint32 gasForCallExactCheck
    ) external {
        if (nativePremiumPercentage >= 155) revert BlocklockErrors.InvalidPremiumPercentage();

        config.maxGasLimit = maxGasLimit;
        config.gasAfterPaymentCalculation = gasAfterPaymentCalculation;
        config.fulfillmentFlatFeeNativePPM = fulfillmentFlatFeeNativePPM;
        config.weiPerUnitGas = weiPerUnitGas;
        config.blsPairingCheckOverhead = blsPairingCheckOverhead;
        config.nativePremiumPercentage = nativePremiumPercentage;
        config.gasForCallExactCheck = gasForCallExactCheck;
    }
}