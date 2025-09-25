// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {AccessControlEnumerableUpgradeable} from
    "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";

import {ScheduledUpgradeable} from "../scheduled-contract-upgrades/ScheduledUpgradeable.sol";

import {TypesLib} from "../libraries/TypesLib.sol";
import {BlocklockCryptoLib} from "./BlocklockCryptoLib.sol";
import {BlocklockSubscriptionLib, BlocklockErrors} from "./BlocklockSubscriptionLib.sol";
import {BlocklockDSTLib} from "./BlocklockDSTLib.sol";

import {IBlocklockSender} from "../interfaces/IBlocklockSender.sol";
import {IBlocklockReceiver} from "../interfaces/IBlocklockReceiver.sol";
import {IDecryptionSender} from "../interfaces/IDecryptionSender.sol";

import {DecryptionReceiverBase} from "../decryption-requests/DecryptionReceiverBase.sol";
import {BlocklockFeeCollector} from "./BlocklockFeeCollector.sol";

import {CallWithExactGas} from "../libraries/CallWithExactGas.sol";

/// @title BlocklockSender Contract
/// @author Randamu
/// @notice This contract is responsible for managing the blocklock sending functionality,
///         including handling requests, decryption keys, decryption, fees, and access control.
/// @dev The contract integrates multiple functionalities including decryption receiver capabilities,
///      fee collection, and role-based access control. It is also upgradeable and follows the UUPS pattern.
///      The contract implements the `IBlocklockSender` interface and uses `DecryptionReceiverBase` for handling decryption logic.
///      Additionally, it collects fees via `BlocklockFeeCollector` and uses OpenZeppelin's upgradeable and access control mechanisms.
contract BlocklockSender is
    IBlocklockSender,
    DecryptionReceiverBase,
    BlocklockFeeCollector,
    ScheduledUpgradeable,
    AccessControlEnumerableUpgradeable
{
    using CallWithExactGas for bytes;

    /// @notice This contract manages blocklock requests, decryption keys, and administrative roles.
    /// @dev The contract includes constants related to blocklock schemes, decryption key processing, and events for blocklock requests and callbacks.
    ///      It also defines an `ADMIN_ROLE` for managing access control and updates to decryption sender.

    /// @notice Domain separation tags for cryptographic operations
    bytes public DST_H3;
    bytes public DST_H4;

    /// @notice Mapping of request ID to blocklock request data
    mapping(uint256 => TypesLib.BlocklockRequest) public blocklockRequestsWithDecryptionKey;

    /// @notice Event emitted when a blocklock request is made
    /// @param requestId The unique identifier of the blocklock request
    /// @param condition The condition for decryption of the ciphertext
    /// @param ciphertext The ciphertext associated with the blocklock request
    /// @param requester The address of the requester
    /// @param requestedAt The timestamp when the request was made
    /// @dev This event is emitted after a blocklock request has been successfully processed
    event BlocklockRequested(
        uint256 indexed requestId,
        bytes condition,
        TypesLib.Ciphertext ciphertext,
        address indexed requester,
        uint256 requestedAt
    );

    /// @notice Event emitted when a blocklock callback is successful
    /// @param requestId The unique identifier of the blocklock request
    /// @param condition The condition for decryption of the ciphertext
    /// @param ciphertext The ciphertext associated with the blocklock request
    /// @param decryptionKey The decryption key used for the blocklock
    /// @dev This event is emitted when the blocklock callback is successfully processed and the decryption key is provided
    event BlocklockCallbackSuccess(
        uint256 indexed requestId, bytes condition, TypesLib.Ciphertext ciphertext, bytes decryptionKey
    );

    /// @notice Error thrown when a blocklock callback fails
    /// @param requestId The request ID of the failed blocklock callback
    /// @dev This error is used to indicate that the blocklock callback process has failed, providing the request ID for troubleshooting
    event BlocklockCallbackFailed(uint256 indexed requestId);

    /// @notice Event emitted when the decryption sender address is updated
    /// @param decryptionSender The new decryption sender address
    /// @dev This event is triggered when the address of the decryption sender is updated, allowing for tracking of the changes
    event DecryptionSenderUpdated(address indexed decryptionSender);

    /// @notice Modifier that restricts access to only accounts with the admin role
    /// @dev This modifier checks that the caller has the `ADMIN_ROLE` before allowing the function to be executed.
    modifier onlyAdmin() {
        _checkRole(keccak256("ADMIN_ROLE"));
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner, address _decryptionSender, address _contractUpgradeBlsValidator)
        public
        initializer
    {
        __UUPSUpgradeable_init();
        __AccessControlEnumerable_init();
        __ScheduledUpgradeable_init(_contractUpgradeBlsValidator, 2 days);

        if (!_grantRole(keccak256("ADMIN_ROLE"), owner)) revert BlocklockErrors.GrantRoleFailed();
        if (!_grantRole(DEFAULT_ADMIN_ROLE, owner)) revert BlocklockErrors.GrantRoleFailed();
        decryptionSender = IDecryptionSender(_decryptionSender);

        (,, DST_H3, DST_H4) = BlocklockDSTLib.initializeDSTs(getChainId());
    }

    /// @notice Requests blocklock with direct payment
    /// @param callbackGasLimit Gas limit for callback (0 to maxGasLimit)
    /// @param condition Condition for decryption as bytes
    /// @param ciphertext Ciphertext for the blocklock request
    function requestBlocklock(
        uint32 callbackGasLimit,
        bytes calldata condition,
        TypesLib.Ciphertext calldata ciphertext
    ) external payable onlyConfiguredNotDisabled returns (uint256) {
        uint256 decryptionRequestId = requestBlocklockWithSubscription(
            callbackGasLimit,
            0, // no subId for direct funding requests
            condition,
            ciphertext
        );
        return decryptionRequestId;
    }

    /// @notice Requests blocklock with subscription
    /// @param callbackGasLimit Gas limit for callback
    /// @param subId Subscription ID (0 for direct funding)
    /// @param condition Condition for decryption
    /// @param ciphertext Ciphertext for the request
    /// @return requestId Unique request identifier
    function requestBlocklockWithSubscription(
        uint32 callbackGasLimit,
        uint256 subId,
        bytes memory condition,
        TypesLib.Ciphertext calldata ciphertext
    ) public payable onlyConfiguredNotDisabled returns (uint256) {
        if (subId == 0 && msg.value == 0) revert BlocklockErrors.DirectFundingRequired();

        /// @dev subId must be zero for direct funding or non zero for active subscription
        _validateCallbackGasLimitAndUpdateSubscription(callbackGasLimit, subId);

        uint256 decryptionRequestId = _registerCiphertext("BN254-BLS-BLOCKLOCK", abi.encode(ciphertext), condition);

        blocklockRequestsWithDecryptionKey[decryptionRequestId] = TypesLib.BlocklockRequest({
            subId: subId,
            directFundingFeePaid: msg.value,
            callbackGasLimit: callbackGasLimit,
            decryptionRequestId: decryptionRequestId,
            condition: condition,
            ciphertext: ciphertext,
            signature: hex"",
            decryptionKey: hex"",
            callback: msg.sender
        });

        emit BlocklockRequested(decryptionRequestId, condition, ciphertext, msg.sender, block.timestamp);
        return decryptionRequestId;
    }

    /// @notice Validates subscription and gas limit
    /// @param _callbackGasLimit Gas limit for callback
    /// @param _subId Subscription ID (0 for direct funding)
    function _validateCallbackGasLimitAndUpdateSubscription(uint32 _callbackGasLimit, uint256 _subId) internal {
        if (_subId > 0) {
            BlocklockSubscriptionLib.validateSubscriptionAndUpdateConsumer(
                _callbackGasLimit, _subId, s_config.maxGasLimit, s_subscriptionConfigs, s_consumers
            );
        } else {
            uint256 price = _calculateRequestPriceNative(_callbackGasLimit, tx.gasprice);
            BlocklockSubscriptionLib.validateDirectFundingRequest(_callbackGasLimit, s_config.maxGasLimit, price);
        }
    }

    /// @notice Handles decryption data reception
    /// @param decryptionRequestId Request ID
    /// @param decryptionKey Decryption key
    /// @param signature Key signature
    function onDecryptionDataReceived(uint256 decryptionRequestId, bytes memory decryptionKey, bytes memory signature)
        internal
        override
    {
        uint256 startGas = gasleft();

        TypesLib.BlocklockRequest storage request = blocklockRequestsWithDecryptionKey[decryptionRequestId];
        if (request.decryptionRequestId == 0) revert BlocklockErrors.NoRequestFound();

        bytes memory callbackCallData =
            abi.encodeWithSelector(IBlocklockReceiver.receiveBlocklock.selector, decryptionRequestId, decryptionKey);

        (bool success,) = callbackCallData._callWithExactGasEvenIfTargetIsNoContract(
            request.callback, request.callbackGasLimit, s_config.gasForCallExactCheck
        );
        if (success) {
            request.decryptionKey = decryptionKey;
            request.signature = signature;
            emit BlocklockCallbackSuccess(
                decryptionRequestId, request.condition, request.ciphertext, request.decryptionKey
            );
        } else {
            emit BlocklockCallbackFailed(decryptionRequestId);
        }

        _handlePaymentAndCharge(decryptionRequestId, startGas);
    }

    /// @notice Estimates request price in native tokens
    /// @param _gasLimit Callback gas limit
    /// @param _gasPrice Gas price in wei
    /// @return Estimated price in wei
    function estimateRequestPriceNative(uint32 _gasLimit, uint256 _gasPrice)
        external
        view
        override (BlocklockFeeCollector, IBlocklockSender)
        returns (uint256)
    {
        return _calculateRequestPriceNative(_gasLimit, _gasPrice);
    }

    /// @notice Calculates request price in native tokens
    /// @param _gasLimit Callback gas limit
    /// @return Total price in wei
    function calculateRequestPriceNative(uint32 _gasLimit)
        public
        view
        override (BlocklockFeeCollector, IBlocklockSender)
        returns (uint256)
    {
        return _calculateRequestPriceNative(_gasLimit, tx.gasprice);
    }

    /// @notice Handles the payment and charges for a request based on the subscription or direct funding.
    /// @dev This function calculates the payment for a given request, either based on a subscription or direct funding.
    /// @dev It updates the subscription and consumer state and
    ///     charges the appropriate amount based on the gas usage and payment parameters.
    /// @param requestId The ID of the request to handle payment for.
    /// @param startGas The amount of gas used at the start of the transaction,
    ///     used for calculating payment based on gas consumption.
    function _handlePaymentAndCharge(uint256 requestId, uint256 startGas) internal override {
        TypesLib.BlocklockRequest memory request = getRequest(requestId);

        uint96 payment;
        if (request.subId > 0) {
            uint96 calculatedPayment = _calculatePaymentAmountNative(startGas, tx.gasprice);
            payment = BlocklockSubscriptionLib.handleSubscriptionPayment(
                request, calculatedPayment, s_subscriptions, s_consumers
            );
        } else {
            payment = BlocklockSubscriptionLib.handleDirectFundingPayment(request);
        }

        _chargePayment(payment, request.subId);
    }

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
    function decrypt(TypesLib.Ciphertext calldata ciphertext, bytes calldata decryptionKey)
        public
        view
        returns (bytes memory)
    {
        return BlocklockCryptoLib.decrypt(ciphertext, decryptionKey, DST_H3, DST_H4);
    }

    /// @notice Sets a new decryption sender address
    /// @param newDecryptionSender The address of the new decryption sender contract
    /// @dev Only an admin can call this function. The function updates the `decryptionSender` address
    /// and emits a `DecryptionSenderUpdated` event with the new address.
    /// @dev The `DecryptionSenderUpdated` event is emitted to notify listeners of the change in decryption sender address.
    function setDecryptionSender(address newDecryptionSender) external onlyAdmin {
        decryptionSender = IDecryptionSender(newDecryptionSender);
        emit DecryptionSenderUpdated(newDecryptionSender);
    }

    /// @notice disable this contract so that new requests will be rejected. When disabled, new requests
    /// @notice will revert but existing requests can still be fulfilled.
    function disable() external override onlyAdmin {
        s_disabled = true;

        emit Disabled();
    }

    /// @notice Enables the contract, allowing new requests to be accepted.
    /// @dev Can only be called by an admin.
    function enable() external override onlyAdmin {
        s_disabled = false;
        emit Enabled();
    }

    /// @notice Sets contract configuration parameters
    /// @param maxGasLimit Maximum gas limit for requests
    /// @param gasAfterPaymentCalculation Gas for post-payment accounting
    /// @param fulfillmentFlatFeeNativePPM Flat fee in PPM (1M PPM = 100%)
    /// @param weiPerUnitGas Wei per gas unit
    /// @param blsPairingCheckOverhead Gas overhead for BLS operations
    /// @param nativePremiumPercentage Premium percentage for native payments
    /// @param gasForCallExactCheck Gas for exact gas calls
    function setConfig(
        uint32 maxGasLimit,
        uint32 gasAfterPaymentCalculation,
        uint32 fulfillmentFlatFeeNativePPM,
        uint32 weiPerUnitGas,
        uint32 blsPairingCheckOverhead,
        uint8 nativePremiumPercentage,
        uint32 gasForCallExactCheck
    ) external override onlyAdmin {
        if (PREMIUM_PERCENTAGE_MAX <= nativePremiumPercentage) revert BlocklockErrors.InvalidPremiumPercentage();

        s_config = Config({
            maxGasLimit: maxGasLimit,
            gasAfterPaymentCalculation: gasAfterPaymentCalculation,
            fulfillmentFlatFeeNativePPM: fulfillmentFlatFeeNativePPM,
            weiPerUnitGas: weiPerUnitGas,
            blsPairingCheckOverhead: blsPairingCheckOverhead,
            nativePremiumPercentage: nativePremiumPercentage,
            gasForCallExactCheck: gasForCallExactCheck
        });

        s_configured = true;

        emit ConfigSet(
            maxGasLimit,
            gasAfterPaymentCalculation,
            fulfillmentFlatFeeNativePPM,
            weiPerUnitGas,
            blsPairingCheckOverhead,
            nativePremiumPercentage,
            gasForCallExactCheck
        );
    }

    /// @notice Gets current configuration parameters
    /// @return maxGasLimit Max gas limit
    /// @return gasAfterPaymentCalculation Post-payment gas
    /// @return fulfillmentFlatFeeNativePPM Flat fee in PPM
    /// @return weiPerUnitGas Wei per gas unit
    /// @return blsPairingCheckOverhead BLS operation overhead
    /// @return nativePremiumPercentage Native payment premium
    /// @return gasForCallExactCheck Exact call gas
    function getConfig() external view returns (uint32, uint32, uint32, uint32, uint32, uint8, uint32) {
        return (
            s_config.maxGasLimit,
            s_config.gasAfterPaymentCalculation,
            s_config.fulfillmentFlatFeeNativePPM,
            s_config.weiPerUnitGas,
            s_config.blsPairingCheckOverhead,
            s_config.nativePremiumPercentage,
            s_config.gasForCallExactCheck
        );
    }

    /// @notice Owner cancel subscription, sends remaining native tokens directly to the subscription owner.
    /// @param subId subscription id
    /// @dev notably can be called even if there are pending requests, outstanding ones may fail onchain
    function ownerCancelSubscription(uint256 subId) external override onlyAdmin {
        address subOwner = s_subscriptionConfigs[subId].owner;
        BlocklockSubscriptionLib.requireValidSubscription(subOwner);
        _cancelSubscriptionHelper(subId, subOwner);
    }

    /// @notice Withdraw native tokens earned through fulfilling requests.
    /// @param recipient The address to send the funds to.
    function withdrawSubscriptionFeesNative(address payable recipient) external override nonReentrant onlyAdmin {
        uint96 amount = s_withdrawableSubscriptionFeeNative;
        _requireSufficientBalance(amount > 0);
        // Prevent re-entrancy by updating state before transfer.
        s_withdrawableSubscriptionFeeNative = 0;
        // For subscription fees, we also deduct amount from s_totalNativeBalance
        // s_totalNativeBalance tracks the total native sent to/from
        // this contract through fundSubscription, cancelSubscription.
        s_totalNativeBalance -= amount;
        _mustSendNative(recipient, amount);
    }

    function withdrawDirectFundingFeesNative(address payable recipient) external override nonReentrant onlyAdmin {
        uint96 amount = s_withdrawableDirectFundingFeeNative;
        _requireSufficientBalance(amount > 0);
        // Prevent re-entrancy by updating state before transfer.
        s_withdrawableDirectFundingFeeNative = 0;

        _mustSendNative(recipient, amount);
    }

    /// @notice Checks whether a Blocklock request is in flight
    /// @param requestId The unique identifier for the Blocklock request
    /// @return A boolean indicating if the request is currently in flight (true) or not (false)
    /// @dev This function retrieves the associated decryption request ID for the given request ID and checks
    /// if the decryption request is still in flight using the `decryptionSender`.
    /// If the `decryptionRequestId` is 0, the request is not in flight.
    function isInFlight(uint256 requestId) external view returns (bool) {
        uint256 signatureRequestId = getRequest(requestId).decryptionRequestId;

        if (signatureRequestId == 0) {
            return false;
        }

        return decryptionSender.isInFlight(signatureRequestId);
    }

    /// @notice Retrieves a Blocklock request by its unique request ID
    /// @param requestId The unique identifier for the Blocklock request
    /// @return r The BlocklockRequest structure containing details of the request
    /// @dev Throws an error if the provided request ID is invalid (decryptionRequestId is 0).
    function getRequest(uint256 requestId) public view returns (TypesLib.BlocklockRequest memory) {
        TypesLib.BlocklockRequest memory r = blocklockRequestsWithDecryptionKey[requestId];
        if (r.decryptionRequestId == 0) revert BlocklockErrors.InvalidRequestId();

        return r;
    }

    /// @notice Returns the version number of the upgradeable contract
    /// @return The version number of the contract as a string
    /// @dev This function is used to identify the current version of the contract for upgrade management and version tracking.
    function version() external pure returns (string memory) {
        return "0.0.1";
    }

    /// @notice Returns the current blockchain chain ID.
    /// @dev Uses inline assembly to retrieve the `chainid` opcode.
    /// @return chainId The current chain ID of the network.
    function getChainId() public view override (IBlocklockSender, ScheduledUpgradeable) returns (uint256 chainId) {
        chainId = super.getChainId();
    }
}
