// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {SubscriptionAPI} from "../subscription/SubscriptionAPI.sol";

import {CallWithExactGas} from "../utils/CallWithExactGas.sol";

abstract contract BlocklockFeeCollector is CallWithExactGas, ReentrancyGuard, SubscriptionAPI {
    /// @dev Upper bound for premium percentages to prevent overflow in fee calculations.
    uint8 internal constant PREMIUM_PERCENTAGE_MAX = 155;

    /// @dev Tracks whether the contract has been configured (required for requests).
    bool public s_configured;

    /// @dev Disables the contract when true. Existing requests can still be fulfilled.
    bool public s_disabled;

    /// @dev Emitted when the contract is enabled.
    event Enabled();

    /// @dev Emitted when the contract is disabled.
    event Disabled();

    /// @dev Emitted for L1 gas fee tracking.
    event L1GasFee(uint256 fee);

    /// @dev Emitted when the contract configuration is updated.
    event ConfigSet(
        uint32 maxGasLimit,
        uint32 gasAfterPaymentCalculation,
        uint32 fulfillmentFlatFeeNativePPM,
        uint8 nativePremiumPercentage
    );

    /// @dev Ensures function is only called when the contract configuration parameters are set and
    /// the contract is not disabled.
    modifier onlyConfiguredNotDisabled() {
        // solhint-disable-next-line gas-custom-errors
        require(s_configured, "Contract is not configured");
        // solhint-disable-next-line gas-custom-errors
        require(!s_disabled, "Contract is disabled");
        _;
    }

    /// @notice Configures the contract's settings.
    /// @dev This function sets the global gas limit, post-fulfillment gas usage, and fee structure.
    ///      Can only be called by an admin.
    /// @param maxGasLimit The maximum gas allowed for a request.
    /// @param gasAfterPaymentCalculation The gas required for post-fulfillment accounting.
    /// @param fulfillmentFlatFeeNativePPM The flat fee (in parts-per-million) for native token payments.
    /// @param nativePremiumPercentage The percentage-based premium for native payments.
    function setConfig(
        uint32 maxGasLimit,
        uint32 gasAfterPaymentCalculation,
        uint32 fulfillmentFlatFeeNativePPM,
        uint8 nativePremiumPercentage
    ) external virtual {}

    function disable() external virtual {}
    function enable() external virtual {}

    function ownerCancelSubscription(uint256 subId) external virtual {}

    function withdrawNative(address payable recipient) external virtual {}

    /// @notice Calculates the price of a request with the given callbackGasLimit at the current
    /// @notice block.
    /// @dev This function relies on the transaction gas price which is not automatically set during
    /// @dev simulation. To estimate the price at a specific gas price, use the estimatePrice function.
    /// @param _callbackGasLimit is the gas limit used to estimate the price.
    function calculateRequestPriceNative(uint32 _callbackGasLimit) public view virtual returns (uint256) {
        return _calculateRequestPriceNative(_callbackGasLimit, tx.gasprice);
    }

    /// @notice Estimates the price of a request with a specific gas limit and gas price.
    /// @dev This is a convenience function that can be called in simulation to better understand
    /// @dev pricing.
    /// @param _callbackGasLimit is the gas limit used to estimate the price.
    /// @param _requestGasPriceWei is the gas price in wei used for the estimation.
    function estimateRequestPriceNative(uint32 _callbackGasLimit, uint256 _requestGasPriceWei)
        external
        view
        virtual
        returns (uint256)
    {
        return _calculateRequestPriceNative(_callbackGasLimit, _requestGasPriceWei);
    }

    /// @notice Calculates the total request price including gas costs and additional fees.
    /// @param _gas The amount of gas required for the request.
    /// @param _requestGasPrice The gas price in wei per gas unit.
    /// @return The total cost in native tokens.
    function _calculateRequestPriceNative(uint256 _gas, uint256 _requestGasPrice) internal view returns (uint256) {
        // costWei is the base fee denominated in wei (native)
        // (wei/gas) * gas
        // blocklockSenderCostWei takes into account the L1 posting costs of the fulfillment transaction, if we are on an L2.
        // (wei/gas) * gas + l1wei
        // fixme add gas used by decryption sender callback
        // e.g., _requestGasPrice * (_gas + _getDecryptionSenderGasOverhead() + _getL1CostWei());
        uint256 blocklockSenderCostWei = _requestGasPrice * (_gas + _getL1CostWei());

        // blocklockSenderCostWithPremiumAndFlatFeeWei is the blocklockSender cost with the percentage premium and flat fee applied
        // blocklockSender cost * premium multiplier + flat fee
        uint256 blocklockSenderCostWithPremiumAndFlatFeeWei = (
            (blocklockSenderCostWei * (s_config.nativePremiumPercentage + 100)) / 100
        ) + (1e12 * uint256(s_config.fulfillmentFlatFeeNativePPM));

        return blocklockSenderCostWithPremiumAndFlatFeeWei;
    }

    /// @notice Returns the L1 fee for fulfilling a request.
    /// @dev Always returns `0` on L1 chains. Should be overridden for L2 chains.
    /// @return The L1 fee in wei.
    function _getL1CostWei() internal view virtual returns (uint256) {
        return 0;
    }

    /// @notice Returns the L1 fee for the calldata payload.
    /// @dev Always returns `0` on L1 chains. Should be overridden for L2 chains.
    // /// @param data The calldata payload.
    /// @return The L1 fee in wei.
    function _getL1CostWei(bytes calldata /*data*/ ) internal view virtual returns (uint256) {
        return 0;
    }

    /// @dev Calculates extra amount of gas required for running an assembly call() post-EIP150.
    function _getEIP150Overhead(uint32 gas) internal pure returns (uint32) {
        return gas / 63 + 1;
    }

    /// @notice Calculates the payment amount in native tokens, considering L1 gas fees if applicable.
    /// @param startGas The initial gas measurement.
    /// @param weiPerUnitGas The gas price in wei.
    /// @return The total payment amount in native tokens.
    function _calculatePaymentAmountNative(uint256 startGas, uint256 weiPerUnitGas) internal returns (uint96) {
        // Will return non-zero on chains that have this enabled
        uint256 l1CostWei = _getL1CostWei(msg.data);
        // calculate the payment without the premium
        uint256 baseFeeWei = weiPerUnitGas * (s_config.gasAfterPaymentCalculation + startGas - gasleft());
        // calculate flat fee in native
        uint256 flatFeeWei = 1e12 * uint256(s_config.fulfillmentFlatFeeNativePPM);
        // emit this event only if this is an L2 chain that needs to cover for L1 gas fees
        if (l1CostWei > 0) {
            emit L1GasFee(l1CostWei);
        }

        return uint96((((l1CostWei + baseFeeWei) * (100 + s_config.nativePremiumPercentage)) / 100) + flatFeeWei);
    }

    /// @notice Charges a payment against a subscription and updates contract balances
    /// @dev If `subId` is 0, payment is treated as a direct charge (no subscription tracking)
    /// @param payment The amount to charge in native tokens
    /// @param subId The subscription ID to charge; 0 means no subscription
    function _chargePayment(uint96 payment, uint256 subId) internal {
        Subscription storage subcription = s_subscriptions[subId];

        if (subId > 0) {
            uint96 prevBal = subcription.nativeBalance;

            _requireSufficientBalance(prevBal >= payment);
            
            subcription.nativeBalance = prevBal - payment;
        }

        s_withdrawableNative += payment;
    }

    /// @notice Handles payment logic and charges gas fees for a given request
    /// @dev Intended to be overridden by derived contracts to implement custom payment handling
    /// @param requestId The unique identifier of the request being processed
    /// @param startGas The amount of gas available at the start of the function execution
    function _handlePaymentAndCharge(uint256 requestId, uint256 startGas) internal virtual {}
}
