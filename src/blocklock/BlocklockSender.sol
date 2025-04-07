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
import {ISignatureSender} from "../interfaces/ISignatureSender.sol";

import {SignatureReceiverBase} from "../signature-requests/SignatureReceiverBase.sol";

import {DecryptionReceiverBase} from "../decryption-requests/DecryptionReceiverBase.sol";
import {IDecryptionSender} from "../interfaces/IDecryptionSender.sol";

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

    modifier onlyOwner() {
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
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /**
     * @dev See {IBlocklockSender-requestBlocklock}.
     */
    function requestBlocklock(uint256 blockHeight, TypesLib.Ciphertext calldata ciphertext)
        external
        returns (
            // payable // fixme uncomment code
            // onlyConfiguredNotDisabled // fixme uncomment code
            uint256
        )
    {
        require(blockHeight > block.number, "blockHeight must be strictly greater than current");

        TypesLib.BlocklockRequest memory r = TypesLib.BlocklockRequest({
            decryptionRequestID: 0,
            blockHeight: blockHeight,
            ciphertext: ciphertext,
            signature: hex"",
            decryptionKey: hex"",
            callback: msg.sender
        });

        // fixme uncomment code
        // subId can be zero for direct funding or non zero for active subscription
        // callbackGasLimit can be zero but user will not get anything in callback. Only signature verification in
        // decryption sender will be done and decryption key saved
        // _validateAndUpdateSubscription(callbackGasLimit, subId);

        // New decryption request
        bytes memory condition = abi.encode(blockHeight);

        uint256 decryptionRequestID = decryptionSender.registerCiphertext(SCHEME_ID, abi.encode(ciphertext), condition);
        r.decryptionRequestID = decryptionRequestID;

        // Store the signature requestID for this blockHeight
        blocklockRequestsWithDecryptionKey[decryptionRequestID] = r;

        emit BlocklockRequested(decryptionRequestID, blockHeight, ciphertext, msg.sender, block.timestamp);
        return decryptionRequestID;
    }

    // fixme natspec
    function _validateAndUpdateSubscription(uint32 _callbackGasLimit, uint256 _subId) internal {
        // fixme test subId always > 0 for createSubscription() in SubscriptionAPI
        uint32 callbackGasLimit = 0;
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

            callbackGasLimit = _callbackGasLimit;
        } else {
            uint32 eip150Overhead = _getEIP150Overhead(_callbackGasLimit);
            uint256 price = _calculateRequestPriceNative(_callbackGasLimit, tx.gasprice);
            callbackGasLimit = _callbackGasLimit + eip150Overhead;

            require(msg.value >= price, "Fee too low");
        }

        // No lower bound on the requested gas limit. A user could request 0
        // and they would simply be billed for the signature verification and wouldn't be
        // able to do anything with the decryption key.
        require(callbackGasLimit <= s_config.maxGasLimit, "Callback gasLimit too high");
    }

    /**
     * @dev See {DecryptionReceiverBase-onDecryptionDataReceived}.
     */
    function onDecryptionDataReceived(uint256 decryptionRequestID, bytes memory decryptionKey, bytes memory signature)
        internal
        override
    {
        // fixme uncomment code
        // uint256 startGas = gasleft();

        TypesLib.BlocklockRequest memory r = blocklockRequestsWithDecryptionKey[decryptionRequestID];
        require(r.decryptionRequestID > 0, "No request for request id");

        r.signature = signature;

        (bool success,) = r.callback.call(
            abi.encodeWithSelector(IBlocklockReceiver.receiveBlocklock.selector, decryptionRequestID, decryptionKey)
        );

        // fixme uncomment code
        // fixme ensure _handlePaymentAndCharge is called in both if else cases to charge before revert
        if (!success) {
            // _handlePaymentAndCharge(decryptionRequestID, startGas);
            revert BlocklockCallbackFailed(decryptionRequestID);
        } else {
            emit BlocklockCallbackSuccess(decryptionRequestID, r.blockHeight, r.ciphertext, decryptionKey);
            blocklockRequestsWithDecryptionKey[decryptionRequestID].decryptionKey = decryptionKey;
            blocklockRequestsWithDecryptionKey[decryptionRequestID].signature = signature;
            // _handlePaymentAndCharge(decryptionRequestID, startGas);
        }
    }

    // fixme natspec
    function _handlePaymentAndCharge(uint256 requestId, uint256 startGas) internal override {
        // fixme uncomment code
        // TypesLib.BlocklockRequest memory request = getRequest(requestId);

        // if (request.subId > 0) {
        //     ++s_subscriptions[request.subId].reqCount;
        //     --s_consumers[request.callback][request.subId].pendingReqCount;

        //     uint96 payment = _calculatePaymentAmountNative(startGas, tx.gasprice);
        //     _chargePayment(payment, request.subId);
        // } else {
        //     _chargePayment(uint96(request.directFundingPayment), request.subId);
        // }
    }

    /**
     * Decrypt a ciphertext into a plaintext using a decryption key.
     * @param ciphertext The ciphertext to decrypt.
     * @param decryptionKey The decryption key that can be used to decrypt the ciphertext.
     */
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

    /**
     * @dev See {IBlocklockSender-setDecryptionSender}.
     */
    function setDecryptionSender(address newDecryptionSender) external onlyOwner {
        decryptionSender = IDecryptionSender(newDecryptionSender);
        emit DecryptionSenderUpdated(newDecryptionSender);
    }

    /// @notice disable this contract so that new requests will be rejected. When disabled, new requests
    /// @notice will revert but existing requests can still be fulfilled.
    function disable() external override onlyOwner {
        s_disabled = true;

        emit Disabled();
    }

    /// @notice Enables the contract, allowing new requests to be accepted.
    /// @dev Can only be called by an admin.
    function enable() external override onlyOwner {
        s_disabled = false;
        emit Enabled();
    }

    /**
     * @dev See {BlocklockFeeCollector-setConfig}.
     */
    function setConfig(
        uint32 maxGasLimit,
        uint32 gasAfterPaymentCalculation,
        uint32 fulfillmentFlatFeeNativePPM,
        uint8 nativePremiumPercentage
    ) external override onlyOwner {
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
    function ownerCancelSubscription(uint256 subId) external override onlyOwner {
        address subOwner = s_subscriptionConfigs[subId].owner;
        _requireValidSubscription(subOwner);
        _cancelSubscriptionHelper(subId, subOwner);
    }

    /// @notice withdraw native earned through fulfilling requests
    /// @param recipient where to send the funds
    function withdrawNative(address payable recipient) external override nonReentrant onlyOwner {
        uint96 amount = s_withdrawableNative;
        _requireSufficientBalance(amount > 0);
        // Prevent re-entrancy by updating state before transfer.
        s_withdrawableNative = 0;
        s_totalNativeBalance -= amount;
        _mustSendNative(recipient, amount);
    }

    /**
     * @dev See {ISignatureSender-isInFlight}.
     */
    function isInFlight(uint256 requestID) external view returns (bool) {
        uint256 signatureRequestID = getRequest(requestID).decryptionRequestID;

        if (signatureRequestID == 0) {
            return false;
        }

        return decryptionSender.isInFlight(signatureRequestID);
    }

    /**
     * @dev See {IBlocklockSender-getRequest}.
     */
    function getRequest(uint256 requestID) public view returns (TypesLib.BlocklockRequest memory) {
        TypesLib.BlocklockRequest memory r = blocklockRequestsWithDecryptionKey[requestID];
        require(r.decryptionRequestID > 0, "invalid requestID");

        return r;
    }

    /**
     * @dev Returns the version number of the upgradeable contract.
     */
    function version() external pure returns (string memory) {
        return "0.0.1";
    }

    // fixme review and modify code for retry
    // if we allow users call retry, why should they bother calling it and paying when they can simply read
    // the request data from blocklocksender or decryptionsender?
    // chainlinkvrf does not have retry.
    // In chainlink vrfwrapperpluswrapper, for failed callbacks, nothing is stored in the contract, only
    // event emitted and callback is deleted at the start of the function call
    // in chainlink vrf coordinator, function fulfillRandomWords(, keys are deleted and no success checks
    // they simply emit event with whatever the success bool was.
    // delete s_requestCommitments[output.requestId];
    // bool success = _deliverRandomness(output.requestId, rc, randomWords);
    /*
    function fulfillRandomWords(uint256 _requestId, uint256[] calldata _randomWords) internal override {
    Callback memory callback = s_callbacks[_requestId];
    delete s_callbacks[_requestId];

    address callbackAddress = callback.callbackAddress;
    // solhint-disable-next-line gas-custom-errors
    require(callbackAddress != address(0), "request not found"); // This should never happen

    VRFV2PlusWrapperConsumerBase c;
    bytes memory resp = abi.encodeWithSelector(c.rawFulfillRandomWords.selector, _requestId, _randomWords);

    bool success = _callWithExactGas(callback.callbackGasLimit, callbackAddress, resp);
    if (!success) {
      emit WrapperFulfillmentFailed(_requestId, callbackAddress);
    }
    }
    */

    /// @notice Allows any direct funding request owner/callback to retry
    /// a failed callback for a direct funding request.
    /// @dev The caller must pay the gas cost for retrying the callback execution.
    ///      Ensures that a failed callback exists and that sufficient funds are provided.
    /// @param requestID The ID of the failed decryption request.
    /// @param newCallbackGasLimit The new gas limit for retrying the callback.
    function retryCallbackWithDirectFunding(uint256 requestID, uint32 newCallbackGasLimit) external payable {
        // require(hasErrored(requestID), "No failed callback with specified requestID");

        // uint256 requestPrice = calculateRequestPriceNative(newCallbackGasLimit);
        // require(msg.value >= requestPrice, "Insufficient native token for retry");

        // TypesLib.DecryptionRequest memory request = requests[requestID];

        // bytes memory response =
        //     abi.encodeWithSelector(IDecryptionReceiver.receiveDecryptionKey.selector, requestID, request.decryptionKey);

        // bool success = _callWithExactGas(request.callbackGasLimit, request.callback, response);

        // if (!success) {
        //     emit DecryptionReceiverCallbackFailed(requestID, request.subId, request.callback);
        // } else {
        //     erroredRequestIds.remove(requestID);
        //     fulfilledRequestIds.add(requestID);
        //     emit DecryptionReceiverCallbackSuccess(
        //         requestID, request.subId, request.callback, request.decryptionKey, request.signature
        //     );
        // }

        // // Collect direct funding payment
        // _chargePayment(uint96(msg.value), 0);
    }

    function retryCallbackWithSubscription(uint256 requestID, uint32 newCallbackGasLimit) external {}
}
