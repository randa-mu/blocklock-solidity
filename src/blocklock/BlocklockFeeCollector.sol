// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {SubscriptionAPI} from "../subscription/SubscriptionAPI.sol";

abstract contract BlocklockFeeCollector is ReentrancyGuard, SubscriptionAPI {
    /// @dev Gas required for exact EXTCODESIZE call and additional operations.
    uint256 internal constant GAS_FOR_CALL_EXACT_CHECK = 5_000;

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

    // fixme override with modifier
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
    function calculateRequestPriceNative(uint32 _callbackGasLimit) public view returns (uint256) {
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
        // fixme rename coordinator
        // coordinatorCostWei takes into account the L1 posting costs of the fulfillment transaction, if we are on an L2.
        // (wei/gas) * gas + l1wei
        uint256 coordinatorCostWei = _requestGasPrice * (_gas + _getL1CostWei());

        // coordinatorCostWithPremiumAndFlatFeeWei is the coordinator cost with the percentage premium and flat fee applied
        // coordinator cost * premium multiplier + flat fee
        uint256 coordinatorCostWithPremiumAndFlatFeeWei = (
            (coordinatorCostWei * (s_config.nativePremiumPercentage + 100)) / 100
        ) + (1e12 * uint256(s_config.fulfillmentFlatFeeNativePPM));

        return coordinatorCostWithPremiumAndFlatFeeWei;
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

    /// @dev Calls the target address with exactly `gasAmount` gas and provided `data` as calldata.
    /// @notice Reverts if at least `gasAmount` gas is not available.
    /// @param gasAmount The exact amount of gas to send with the call.
    /// @param target The address to call.
    /// @param data The calldata to send with the call.
    /// @return success A boolean indicating whether the call was successful.
    function _callWithExactGas(uint256 gasAmount, address target, bytes memory data) internal returns (bool success) {
        assembly {
            let g := gas()
            // Compute g -= GAS_FOR_CALL_EXACT_CHECK and check for underflow
            // The gas actually passed to the callee is min(gasAmount, 63//64*gas available).
            // We want to ensure that we revert if gasAmount >  63//64*gas available
            // as we do not want to provide them with less, however that check itself costs
            // gas.  GAS_FOR_CALL_EXACT_CHECK ensures we have at least enough gas to be able
            // to revert if gasAmount >  63//64*gas available.
            if lt(g, GAS_FOR_CALL_EXACT_CHECK) { revert(0, 0) }
            g := sub(g, GAS_FOR_CALL_EXACT_CHECK)
            // if g - g//64 <= gasAmount, revert
            // (we subtract g//64 because of EIP-150)
            if iszero(gt(sub(g, div(g, 64)), gasAmount)) { revert(0, 0) }
            // solidity calls check that a contract actually exists at the destination, so we do the same
            if iszero(extcodesize(target)) { revert(0, 0) }
            // call and return whether we succeeded. ignore return data
            // call(gas,addr,value,argsOffset,argsLength,retOffset,retLength)
            success := call(gasAmount, target, 0, add(data, 0x20), mload(data), 0, 0)
        }
        return success;
    }

    /// @notice Deducts the payment from the subscription balance or charges direct funding.
    /// @param payment The amount to charge.
    /// @param subId The subscription ID (0 for direct funding).
    function _chargePayment(uint96 payment, uint256 subId) internal {
        Subscription storage subcription = s_subscriptions[subId];
        if (subId > 0) {
            // check that subscription can cover the payment
            uint96 prevBal = subcription.nativeBalance;
            _requireSufficientBalance(prevBal >= payment);
            // deduct payment from subscription
            subcription.nativeBalance = prevBal - payment;
            // allocate payment to withdrawable native token balance for this contract
            s_withdrawableNative += payment;
        } else {
            // uint96 prevBal = subcription.nativeBalance;
            // _requireSufficientBalance(prevBal >= payment);
            s_withdrawableNative += payment;
        }
    }

    function _handlePaymentAndCharge(uint256 requestId, uint256 startGas) internal virtual {}
}
