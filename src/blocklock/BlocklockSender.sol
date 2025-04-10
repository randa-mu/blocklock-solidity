// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {AccessControlEnumerableUpgradeable} from
    "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {TypesLib} from "../libraries/TypesLib.sol";
import {BLS} from "../libraries/BLS.sol";
import {IBlocklockSender} from "../interfaces/IBlocklockSender.sol";
import {IBlocklockReceiver} from "../interfaces/IBlocklockReceiver.sol";
import {IDecryptionSender} from "../interfaces/IDecryptionSender.sol";

import {DecryptionReceiverBase} from "../decryption-requests/DecryptionReceiverBase.sol";
import {BlocklockFeeCollector} from "./BlocklockFeeCollector.sol";

contract BlocklockSender is
    IBlocklockSender,
    DecryptionReceiverBase,
    BlocklockFeeCollector,
    Initializable,
    UUPSUpgradeable,
    AccessControlEnumerableUpgradeable
{
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    string public constant SCHEME_ID = "BN254-BLS-BLOCKLOCK";
    bytes public constant DST_H1_G1 = "BLOCKLOCK_BN254G1_XMD:KECCAK-256_SVDW_RO_H1_";
    bytes public constant DST_H2 = "BLOCKLOCK_BN254_XMD:KECCAK-256_H2_";
    bytes public constant DST_H3 = "BLOCKLOCK_BN254_XMD:KECCAK-256_H3_";
    bytes public constant DST_H4 = "BLOCKLOCK_BN254_XMD:KECCAK-256_H4_";

    // Mapping from decryption requestID to conditional decryption request
    mapping(uint256 => TypesLib.BlocklockRequest) public blocklockRequestsWithDecryptionKey;

    event BlocklockRequested(
        uint256 indexed requestID,
        uint256 blockHeight,
        TypesLib.Ciphertext ciphertext,
        address indexed requester,
        uint256 requestedAt
    );
    event BlocklockCallbackSuccess(
        uint256 indexed requestID, uint256 blockHeight, TypesLib.Ciphertext ciphertext, bytes decryptionKey
    );

    event DecryptionSenderUpdated(address indexed decryptionSender);

    error BlocklockCallbackFailed(uint256 requestID);

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
    }

    // OVERRIDDEN UPGRADE FUNCTIONS
    function _authorizeUpgrade(address newImplementation) internal override onlyAdmin {}

    /**
     * @dev See {IBlocklockSender-requestBlocklock}.
     */
    function requestBlocklock(
        uint32 callbackGasLimit,
        uint256 subId,
        uint256 blockHeight,
        TypesLib.Ciphertext calldata ciphertext
    ) external payable onlyConfiguredNotDisabled returns (uint256) {
        require(blockHeight > block.number, "blockHeight must be strictly greater than current");

        if (subId == 0) {
            require(msg.value > 0, "Direct funding required for request fulfillment callback");
        }

        TypesLib.BlocklockRequest memory r = TypesLib.BlocklockRequest({
            subId: subId,
            directFundingPayment: msg.value,
            decryptionRequestID: 0,
            blockHeight: blockHeight,
            ciphertext: ciphertext,
            signature: hex"",
            decryptionKey: hex"",
            callback: msg.sender
        });

        // subId can be zero for direct funding or non zero for active subscription
        // fixme test that callbackGasLimit can be zero but user will not get anything in callback. Only signature verification in
        // decryption sender will be done and decryption key saved
        uint32 callbackGasLimitWithOverhead = _validateAndUpdateSubscription(callbackGasLimit, subId);

        // New decryption request
        bytes memory condition = abi.encode(blockHeight);

        uint256 decryptionRequestID = decryptionSender.registerCiphertext(
            SCHEME_ID, callbackGasLimitWithOverhead, abi.encode(ciphertext), condition
        );
        r.decryptionRequestID = uint64(decryptionRequestID);

        // Store the signature requestID for this blockHeight
        blocklockRequestsWithDecryptionKey[decryptionRequestID] = r;

        emit BlocklockRequested(decryptionRequestID, blockHeight, ciphertext, msg.sender, block.timestamp);
        return decryptionRequestID;
    }

    /// @notice Validates the subscription if subId > 0 and _callbackGasLimit
    /// @notice and updates the subscription for a given consumer.
    /// @dev This function checks the validity of the subscription and updates the subscription's state.
    /// @dev If the subscription ID is greater than zero, it ensures that the consumer has an active subscription.
    /// @dev If the subscription ID is zero, it processes a new subscription by calculating the necessary fees.
    /// @param _callbackGasLimit The gas limit for the callback function.
    /// @param _subId The subscription ID. If greater than zero, it indicates an existing subscription, otherwise, a new subscription is created.
    function _validateAndUpdateSubscription(uint32 _callbackGasLimit, uint256 _subId)
        internal
        returns (uint32 callbackGasLimitWithOverhead)
    {
        // fixme test subId always > 0 for createSubscription() in SubscriptionAPI
        if (_subId > 0) {
            _requireValidSubscription(s_subscriptionConfigs[_subId].owner);
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

        // No lower bound on the requested gas limit. A user could request 0
        // and they would simply be billed for the signature verification and wouldn't be
        // able to do anything with the decryption key.
        require(_callbackGasLimit <= s_config.maxGasLimit, "Callback gasLimit too high");

        uint32 eip150Overhead = _getEIP150Overhead(_callbackGasLimit);
        callbackGasLimitWithOverhead = _callbackGasLimit + eip150Overhead;
    }

    /**
     * @dev See {DecryptionReceiverBase-onDecryptionDataReceived}.
     */
    function onDecryptionDataReceived(uint256 decryptionRequestID, bytes memory decryptionKey, bytes memory signature)
        internal
        override
    {
        uint256 startGas = gasleft();

        TypesLib.BlocklockRequest memory r = blocklockRequestsWithDecryptionKey[decryptionRequestID];
        require(r.decryptionRequestID > 0, "No request for request id");

        r.signature = signature;

        (bool success,) = r.callback.call(
            abi.encodeWithSelector(IBlocklockReceiver.receiveBlocklock.selector, decryptionRequestID, decryptionKey)
        );

        if (!success) {
            revert BlocklockCallbackFailed(decryptionRequestID);
        } else {
            emit BlocklockCallbackSuccess(decryptionRequestID, r.blockHeight, r.ciphertext, decryptionKey);
            blocklockRequestsWithDecryptionKey[decryptionRequestID].decryptionKey = decryptionKey;
            blocklockRequestsWithDecryptionKey[decryptionRequestID].signature = signature;
        }
        _handlePaymentAndCharge(decryptionRequestID, startGas);
    }

    function estimateRequestPriceNative(uint32 _callbackGasLimit, uint256 _requestGasPriceWei)
        external
        view
        override(BlocklockFeeCollector, IBlocklockSender)
        returns (uint256)
    {
        return _calculateRequestPriceNative(_callbackGasLimit, _requestGasPriceWei);
    }

    function calculateRequestPriceNative(uint32 _callbackGasLimit)
        public
        view
        override(BlocklockFeeCollector, IBlocklockSender)
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
            _chargePayment(uint96(request.directFundingPayment), request.subId);
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
    /// @param nativePremiumPercentage The percentage premium applied to the native token cost
    /// @dev Only the contract admin can call this function. It validates that the `nativePremiumPercentage` is greater than a predefined maximum value
    /// (`PREMIUM_PERCENTAGE_MAX`). After validation, it updates the contract's configuration and emits an event `ConfigSet` with the new configuration.
    /// @dev Emits a `ConfigSet` event after successfully setting the new configuration values.
    function setConfig(
        uint32 maxGasLimit,
        uint32 gasAfterPaymentCalculation,
        uint32 fulfillmentFlatFeeNativePPM,
        uint8 nativePremiumPercentage
    ) external override onlyAdmin {
        require(nativePremiumPercentage > PREMIUM_PERCENTAGE_MAX, "Invalid Premium Percentage");

        s_config = Config({
            maxGasLimit: maxGasLimit,
            gasAfterPaymentCalculation: gasAfterPaymentCalculation,
            fulfillmentFlatFeeNativePPM: fulfillmentFlatFeeNativePPM,
            nativePremiumPercentage: nativePremiumPercentage
        });

        s_configured = true;

        emit ConfigSet(maxGasLimit, gasAfterPaymentCalculation, fulfillmentFlatFeeNativePPM, nativePremiumPercentage);
    }

    /// @notice Retrieves the current configuration parameters for the contract
    /// @return maxGasLimit The maximum gas limit allowed for requests
    /// @return gasAfterPaymentCalculation The gas used after the payment calculation
    /// @return fulfillmentFlatFeeNativePPM The flat fee for fulfillment in native tokens, in parts per million (PPM)
    /// @return nativePremiumPercentage The percentage premium applied to the native token cost
    /// @dev This function returns the key configuration values from the contract's settings. These values
    /// are important for calculating request costs and applying the appropriate fees.
    function getConfig()
        external
        view
        returns (
            uint32 maxGasLimit,
            uint32 gasAfterPaymentCalculation,
            uint32 fulfillmentFlatFeeNativePPM,
            uint8 nativePremiumPercentage
        )
    {
        return (
            s_config.maxGasLimit,
            s_config.gasAfterPaymentCalculation,
            s_config.fulfillmentFlatFeeNativePPM,
            s_config.nativePremiumPercentage
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
    function withdrawNative(address payable recipient) external override nonReentrant onlyAdmin {
        uint96 amount = s_withdrawableNative;
        _requireSufficientBalance(amount > 0);
        // Prevent re-entrancy by updating state before transfer.
        s_withdrawableNative = 0;
        s_totalNativeBalance -= amount;
        _mustSendNative(recipient, amount);
    }

    /// @notice Checks whether a Blocklock request is in flight
    /// @param requestID The unique identifier for the Blocklock request
    /// @return A boolean indicating if the request is currently in flight (true) or not (false)
    /// @dev This function retrieves the associated decryption request ID for the given request ID and checks
    /// if the decryption request is still in flight using the `decryptionSender`.
    /// If the `decryptionRequestID` is 0, the request is not in flight.
    function isInFlight(uint256 requestID) external view returns (bool) {
        uint256 signatureRequestID = getRequest(requestID).decryptionRequestID;

        if (signatureRequestID == 0) {
            return false;
        }

        return decryptionSender.isInFlight(signatureRequestID);
    }

    /// @notice Retrieves a Blocklock request by its unique request ID
    /// @param requestID The unique identifier for the Blocklock request
    /// @return r The BlocklockRequest structure containing details of the request
    /// @dev Throws an error if the provided request ID is invalid (decryptionRequestID is 0).
    function getRequest(uint256 requestID) public view returns (TypesLib.BlocklockRequest memory) {
        TypesLib.BlocklockRequest memory r = blocklockRequestsWithDecryptionKey[requestID];
        require(r.decryptionRequestID > 0, "invalid requestID");

        return r;
    }

    /// @notice Returns the version number of the upgradeable contract
    /// @return The version number of the contract as a string
    /// @dev This function is used to identify the current version of the contract for upgrade management and version tracking.
    function version() external pure returns (string memory) {
        return "0.0.1";
    }
}
