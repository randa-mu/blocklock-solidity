// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {AccessControlEnumerableUpgradeable} from
    "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {TypesLib} from "../libraries/TypesLib.sol";
import {BLS} from "../libraries/BLS.sol";
import {BytesLib} from "../libraries/BytesLib.sol";

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
    Initializable,
    UUPSUpgradeable,
    AccessControlEnumerableUpgradeable
{
    using BytesLib for bytes32;
    using CallWithExactGas for bytes;

    /// @notice This contract manages blocklock requests, decryption keys, and administrative roles.
    /// @dev The contract includes constants related to blocklock schemes, decryption key processing, and events for blocklock requests and callbacks.
    ///      It also defines an `ADMIN_ROLE` for managing access control and updates to decryption sender.

    /// @notice The role identifier for the admin role used for access control
    /// @dev This constant is derived from the keccak256 hash of the string "ADMIN_ROLE" and is used in access control checks
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /// @notice The Scheme ID used for the BLS-based blocklock scheme
    /// @dev This constant is used for identifying the BLS blocklock scheme, specifically for BN254 elliptic curve operations
    string public constant SCHEME_ID = "BN254-BLS-BLOCKLOCK";

    /// @notice The domain separation constant used for H1 in the blocklock scheme
    /// @dev This variable is used for hashing and cryptographic operations in the blocklock protocol
    bytes public DST_H1_G1;

    /// @notice The domain separation constant used for H2 in the blocklock scheme
    /// @dev This variable is used for hashing and cryptographic operations in the blocklock protocol
    bytes public DST_H2;

    /// @notice The domain separation constant used for H3 in the blocklock scheme
    /// @dev This variable is used for hashing and cryptographic operations in the blocklock protocol
    bytes public DST_H3;

    /// @notice The domain separation constant used for H4 in the blocklock scheme
    /// @dev This variable is used for hashing and cryptographic operations in the blocklock protocol
    bytes public DST_H4;

    /// @notice Mapping from a decryption request ID to its corresponding blocklock request containing the decryption key
    /// @dev The mapping is used to store blocklock requests with their decryption keys by their unique request IDs
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
        _checkRole(ADMIN_ROLE);
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner, address _decryptionSender) public initializer {
        __UUPSUpgradeable_init();
        __AccessControlEnumerable_init();

        require(_grantRole(ADMIN_ROLE, owner), "Grant role failed");
        require(_grantRole(DEFAULT_ADMIN_ROLE, owner), "Grant role failed");
        decryptionSender = IDecryptionSender(_decryptionSender);

        DST_H1_G1 =
            abi.encodePacked("BLOCKLOCK_BN254G1_XMD:KECCAK-256_SVDW_RO_H1_", bytes32(getChainId()).toHexString(), "_");

        DST_H2 = abi.encodePacked("BLOCKLOCK_BN254_XMD:KECCAK-256_H2_", bytes32(getChainId()).toHexString(), "_");

        DST_H3 = abi.encodePacked("BLOCKLOCK_BN254_XMD:KECCAK-256_H3_", bytes32(getChainId()).toHexString(), "_");

        DST_H4 = abi.encodePacked("BLOCKLOCK_BN254_XMD:KECCAK-256_H4_", bytes32(getChainId()).toHexString(), "_");
    }

    /// @dev Overridden upgrade authorization function to ensure only an authorized caller can authorize upgrades.
    function _authorizeUpgrade(address newImplementation) internal override onlyAdmin {}

    /// @notice Requests a blocklock for a specified condition with the provided ciphertext without a subscription ID.
    /// Requires payment to be made for the request without a subscription.
    /// @param callbackGasLimit How much gas you'd like to receive in your
    /// receiveBlocklock callback. Note that gasleft() inside receiveBlocklock
    /// may be slightly less than this amount because of gas used calling the function
    /// (argument decoding etc.), so you may need to request slightly more than you expect
    /// to have inside receiveBlocklock. The acceptable range is
    /// [0, maxGasLimit]
    /// @param condition The condition for decryption represented as bytes.
    /// The decryption key is sent to the requesting callback / contract address
    /// when the condition is met.
    /// @param ciphertext The ciphertext that will be used in the blocklock request
    /// @dev This function allows users to request a blocklock for a specific condition.
    ///      The blocklock is not associated with any subscription ID
    ///      and requires a ciphertext to be provided. The function checks that the contract is
    ///      configured and not disabled before processing the request.
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

    /// @notice Requests a blocklock for a specified condition with the provided ciphertext and subscription ID
    /// @param callbackGasLimit How much gas you'd like to receive in your
    /// receiveBlocklock callback. Note that gasleft() inside receiveBlocklock
    /// may be slightly less than this amount because of gas used calling the function
    /// (argument decoding etc.), so you may need to request slightly more than you expect
    /// to have inside receiveBlocklock. The acceptable range is
    /// [0, maxGasLimit]
    /// @param subId The subscription ID associated with the request
    /// @param condition The condition for decryption represented as bytes.
    /// The decryption key is sent to the requesting callback / contract address
    /// when the condition is met.
    /// @param ciphertext The ciphertext that will be used in the blocklock request
    /// @return requestId The unique identifier for the blocklock request
    /// @dev This function allows users to request a blocklock for a specific condition.
    ///      The blocklock is associated with a given subscription ID
    ///      and requires a ciphertext to be provided. The function checks that the contract is
    ///      configured and not disabled before processing the request.
    function requestBlocklockWithSubscription(
        uint32 callbackGasLimit,
        uint256 subId,
        bytes memory condition,
        TypesLib.Ciphertext calldata ciphertext
    ) public payable onlyConfiguredNotDisabled returns (uint256) {
        require(subId != 0 || msg.value > 0, "Direct funding required for request fulfillment callback");

        /// @dev subId must be zero for direct funding or non zero for active subscription
        _validateCallbackGasLimitAndUpdateSubscription(callbackGasLimit, subId);

        uint256 decryptionRequestId = _registerCiphertext(SCHEME_ID, abi.encode(ciphertext), condition);

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

    /// @notice Validates the subscription (if subId > 0) and the _callbackGasLimit
    /// @notice and updates the subscription for a given consumer.
    /// @dev This function checks the validity of the subscription and updates the subscription's state.
    /// @dev If the subscription ID is greater than zero, it ensures that the consumer has an active subscription.
    /// @dev If the subscription ID is zero, it processes a new subscription by calculating the necessary fees.
    /// @param _callbackGasLimit The gas limit for the callback function.
    /// @param _subId The subscription ID. If greater than zero, it indicates an existing subscription, otherwise, a new subscription is created.
    function _validateCallbackGasLimitAndUpdateSubscription(uint32 _callbackGasLimit, uint256 _subId) internal {
        // No lower bound on the requested gas limit. A user could request 0 callback gas limit
        // but the overhead added covers bls pairing check operations and decryption as part of the callback
        // and any other added logic in consumer contract might lead to out of gas revert.
        require(_callbackGasLimit <= s_config.maxGasLimit, "Callback gasLimit too high");

        if (_subId > 0) {
            address owner = s_subscriptionConfigs[_subId].owner;
            _requireValidSubscription(owner);
            // Its important to ensure that the consumer is in fact who they say they
            // are, otherwise they could use someone else's subscription balance.
            mapping(uint256 => ConsumerConfig) storage consumerConfigs = s_consumers[msg.sender];

            ConsumerConfig memory consumerConfig = consumerConfigs[_subId];
            require(consumerConfig.active, "No active subscription for caller");

            ++consumerConfig.nonce;
            ++consumerConfig.pendingReqCount;
            consumerConfigs[_subId] = consumerConfig;
        } else {
            uint256 price = _calculateRequestPriceNative(_callbackGasLimit, tx.gasprice);

            require(msg.value >= price, "Fee too low");
        }
    }

    /// @notice Handles the reception of decryption data (decryption key and signature) for a specific decryption request
    /// @param decryptionRequestId The unique identifier for the decryption request, used to correlate the received data
    /// @param decryptionKey The decryption key received, used to decrypt the associated ciphertext
    /// @param signature The signature associated with the decryption key, ensuring its validity
    /// @dev This internal function is intended to be overridden in derived contracts to implement specific logic
    ///      that should be executed upon receiving the decryption data. It is called when decryption data is received
    ///      for a decryption request identified by `decryptionRequestId`.
    function onDecryptionDataReceived(uint256 decryptionRequestId, bytes memory decryptionKey, bytes memory signature)
        internal
        override
    {
        uint256 startGas = gasleft();

        TypesLib.BlocklockRequest storage request = blocklockRequestsWithDecryptionKey[decryptionRequestId];
        require(request.decryptionRequestId != 0, "No request for request id");

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

    /// @notice Estimates the total request price in native tokens based on the provided callback gas limit and requested gas price in wei
    /// @param _callbackGasLimit The gas limit allocated for the callback execution
    /// @param _requestGasPriceWei The gas price in wei for the request
    /// @return The estimated total price for the request in native tokens (wei)
    /// @dev This function calls the internal `_calculateRequestPriceNative` function, passing in the provided callback gas limit and requested gas price in wei
    ///      to estimate the total request price. It overrides the function from both `BlocklockFeeCollector` and `IBlocklockSender` contracts to provide the price estimation.
    function estimateRequestPriceNative(uint32 _callbackGasLimit, uint256 _requestGasPriceWei)
        external
        view
        override (BlocklockFeeCollector, IBlocklockSender)
        returns (uint256)
    {
        return _calculateRequestPriceNative(_callbackGasLimit, _requestGasPriceWei);
    }

    /// @notice Calculates the total request price in native tokens, considering the provided callback gas limit and the current gas price
    /// @param _callbackGasLimit The gas limit allocated for the callback execution
    /// @return The total price for the request in native tokens (wei)
    /// @dev This function calls the internal `_calculateRequestPriceNative` function, passing in the provided callback gas limit and the current
    ///      transaction gas price (`tx.gasprice`) to calculate the total request price. It overrides the function from both `BlocklockFeeCollector`
    ///      and `IBlocklockSender` contracts to provide the request price calculation.
    function calculateRequestPriceNative(uint32 _callbackGasLimit)
        public
        view
        override (BlocklockFeeCollector, IBlocklockSender)
        returns (uint256)
    {
        return _calculateRequestPriceNative(_callbackGasLimit, tx.gasprice);
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

        if (request.subId > 0) {
            ++s_subscriptions[request.subId].reqCount;
            --s_consumers[request.callback][request.subId].pendingReqCount;

            uint96 payment = _calculatePaymentAmountNative(startGas, tx.gasprice);
            _chargePayment(payment, request.subId);
        } else {
            _chargePayment(uint96(request.directFundingFeePaid), request.subId);
        }
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
        require(ciphertext.v.length != 256, "invalid decryption key length");
        require(ciphertext.w.length < 256, "message of unsupported length");

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
        require(equal == success == true, "invalid decryption key / ciphertext registered");

        return m2;
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

    /// @notice Sets the configuration parameters for the contract
    /// @param maxGasLimit The maximum gas limit allowed for requests
    /// @param gasAfterPaymentCalculation The gas used after the payment calculation
    /// @param fulfillmentFlatFeeNativePPM The flat fee for fulfillment in native tokens, in parts per million (PPM)
    /// 1 PPM = 0.0001%, so: 1,000,000 PPM = 100%, 10,000 PPM = 1%, 500 PPM = 0.05%
    /// @param weiPerUnitGas Wei per unit of gas for callback gas measurements
    /// @param blsPairingCheckOverhead Gas overhead for bls pairing checks for signature and decryption key verification
    /// @param nativePremiumPercentage The percentage premium applied to the native token cost
    /// @param gasForCallExactCheck Gas required for exact EXTCODESIZE call and additional operations in CallWithExactGas library
    /// @dev Only the contract admin can call this function. It validates that the `nativePremiumPercentage` is not greater than a predefined maximum value
    /// (`PREMIUM_PERCENTAGE_MAX`). After validation, it updates the contract's configuration and emits an event `ConfigSet` with the new configuration.
    /// @dev Emits a `ConfigSet` event after successfully setting the new configuration values.
    function setConfig(
        uint32 maxGasLimit,
        uint32 gasAfterPaymentCalculation,
        uint32 fulfillmentFlatFeeNativePPM,
        uint32 weiPerUnitGas,
        uint32 blsPairingCheckOverhead,
        uint8 nativePremiumPercentage,
        uint32 gasForCallExactCheck
    ) external override onlyAdmin {
        require(PREMIUM_PERCENTAGE_MAX > nativePremiumPercentage, "Invalid Premium Percentage");

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

    /// @notice Retrieves the current configuration parameters for the contract
    /// @return maxGasLimit The maximum gas limit allowed for requests
    /// @return gasAfterPaymentCalculation The gas used after the payment calculation
    /// @return fulfillmentFlatFeeNativePPM The flat fee for fulfillment in native tokens, in parts per million (PPM)
    /// @return weiPerUnitGas Wei per unit of gas for callback gas measurements
    /// @return blsPairingCheckOverhead Gas overhead for bls pairing checks for signature and decryption key verification
    /// @return nativePremiumPercentage The percentage premium applied to the native token cost
    /// @return gasForCallExactCheck Gas required for exact EXTCODESIZE call and additional operations in CallWithExactGas library.
    /// @dev This function returns the key configuration values from the contract's settings. These values
    /// are important for calculating request costs and applying the appropriate fees.
    function getConfig()
        external
        view
        returns (
            uint32 maxGasLimit,
            uint32 gasAfterPaymentCalculation,
            uint32 fulfillmentFlatFeeNativePPM,
            uint32 weiPerUnitGas,
            uint32 blsPairingCheckOverhead,
            uint8 nativePremiumPercentage,
            uint32 gasForCallExactCheck
        )
    {
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
        _requireValidSubscription(subOwner);
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
        require(r.decryptionRequestId > 0, "invalid requestId");

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
    function getChainId() public view returns (uint256 chainId) {
        assembly {
            chainId := chainid()
        }
    }
}
