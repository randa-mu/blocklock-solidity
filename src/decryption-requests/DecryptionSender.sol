// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {AccessControlEnumerableUpgradeable} from
    "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ContextUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {BLS} from "../libraries/BLS.sol";
import {TypesLib} from "../libraries/TypesLib.sol";
import {BytesLib} from "../libraries/BytesLib.sol";

import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

import {IDecryptionSender} from "../interfaces/IDecryptionSender.sol";
import {IDecryptionReceiver} from "../interfaces/IDecryptionReceiver.sol";
import {IBlocklockSender} from "../interfaces/IBlocklockSender.sol";

import {ISignatureReceiver} from "../interfaces/ISignatureReceiver.sol";
import {ISignatureScheme} from "../interfaces/ISignatureScheme.sol";
import {ISignatureSchemeAddressProvider} from "../interfaces/ISignatureSchemeAddressProvider.sol";

import {CallWithExactGas} from "../utils/CallWithExactGas.sol";

/// @title Decryption Sender contract
/// @notice Contract used to fulfill conditional encryption requests.
/// @notice Passes decryption keys via callbacks to the BlocklockSender contract
/// @notice which then calls the users receiver contract.
contract DecryptionSender is
    IDecryptionSender,
    CallWithExactGas,
    ReentrancyGuard,
    Multicall,
    Initializable,
    UUPSUpgradeable,
    AccessControlEnumerableUpgradeable
{
    using BytesLib for bytes;
    using EnumerableSet for EnumerableSet.UintSet;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    uint256 public lastRequestID = 0;

    // Mapping from decryption requestID to conditional decryption request
    mapping(uint256 => TypesLib.DecryptionRequest) public requests;

    ISignatureSchemeAddressProvider public signatureSchemeAddressProvider;

    EnumerableSet.UintSet private fulfilledRequestIds;
    EnumerableSet.UintSet private unfulfilledRequestIds;
    EnumerableSet.UintSet private erroredRequestIds;

    event SignatureSchemeAddressProviderUpdated(address indexed newSignatureSchemeAddressProvider);
    event DecryptionRequested(
        uint256 indexed requestID,
        address indexed callback,
        string schemeID,
        bytes condition,
        bytes ciphertext,
        uint256 requestedAt
    );
    event DecryptionReceiverCallbackSuccess(uint256 indexed requestID, bytes decryptionKey, bytes signature);

    event DecryptionReceiverCallbackFailed(uint256 requestID);

    modifier onlyOwner() {
        _checkRole(ADMIN_ROLE);
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner, address _signatureSchemeAddressProvider) public initializer {
        __UUPSUpgradeable_init();
        __AccessControlEnumerable_init();

        require(_grantRole(ADMIN_ROLE, owner), "Grant role failed");
        require(_grantRole(DEFAULT_ADMIN_ROLE, owner), "Grant role failed");
        signatureSchemeAddressProvider = ISignatureSchemeAddressProvider(_signatureSchemeAddressProvider);
    }

    // OVERRIDDEN UPGRADE FUNCTIONS
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function _msgSender() internal view override(Context, ContextUpgradeable) returns (address) {
        return msg.sender;
    }

    function _msgData() internal pure override(Context, ContextUpgradeable) returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal pure override(Context, ContextUpgradeable) returns (uint256) {
        return 0;
    }

    /**
     * @dev See {IDecryptionSender-registerCiphertext}.
     */
    function registerCiphertext(
        string calldata schemeID,
        uint32 callbackGasLimit,
        bytes calldata ciphertext,
        bytes calldata condition
    ) external returns (uint256) {
        lastRequestID += 1;

        require(signatureSchemeAddressProvider.isSupportedScheme(schemeID), "Signature scheme not supported");
        require(ciphertext.isLengthWithinBounds(1, 4096), "Message failed length bounds check");
        // condition is optional
        require(condition.isLengthWithinBounds(0, 4096), "Condition failed length bounds check");
        uint256 conditionLength = condition.length;
        if (conditionLength > 0) {
            require(!condition.isAllZero(), "Condition bytes cannot be all zeros");
        }

        address schemeContractAddress = signatureSchemeAddressProvider.getSignatureSchemeAddress(schemeID);
        require(schemeContractAddress > address(0), "invalid signature scheme");

        requests[lastRequestID] = TypesLib.DecryptionRequest({
            schemeID: schemeID,
            ciphertext: ciphertext,
            condition: condition,
            decryptionKey: hex"",
            signature: hex"",
            callback: msg.sender,
            callbackGasLimit: callbackGasLimit,
            isFulfilled: false
        });
        unfulfilledRequestIds.add(lastRequestID);

        emit DecryptionRequested(lastRequestID, msg.sender, schemeID, condition, ciphertext, block.timestamp);

        return lastRequestID;
    }

    /**
     * @dev See {IDecryptionSender-fulfillDecryptionRequest}.
     */
    function fulfillDecryptionRequest(uint256 requestID, bytes calldata decryptionKey, bytes calldata signature)
        external
        nonReentrant
        onlyOwner
    {
        require(isInFlight(requestID), "No request with specified requestID");
        TypesLib.DecryptionRequest memory request = requests[requestID];

        string memory schemeID = request.schemeID;
        address schemeContractAddress = signatureSchemeAddressProvider.getSignatureSchemeAddress(schemeID);
        require(schemeContractAddress > address(0), "invalid scheme");

        ISignatureScheme sigScheme = ISignatureScheme(schemeContractAddress);
        bytes memory messageHash = sigScheme.hashToBytes(request.condition);

        require(
            sigScheme.verifySignature(messageHash, signature, sigScheme.getPublicKeyBytes()),
            "Signature verification failed"
        );

        bytes memory response = abi.encodeWithSelector(
            IDecryptionReceiver.receiveDecryptionData.selector, requestID, decryptionKey, signature
        );

        bool success = _callWithExactGas(request.callbackGasLimit, request.callback, response);

        requests[requestID].decryptionKey = decryptionKey;
        requests[requestID].signature = signature;
        requests[requestID].isFulfilled = true;
        unfulfilledRequestIds.remove(requestID);
        if (!success) {
            erroredRequestIds.add(requestID);
            emit DecryptionReceiverCallbackFailed(requestID);
        } else {
            fulfilledRequestIds.add(requestID);
            emit DecryptionReceiverCallbackSuccess(requestID, decryptionKey, signature);
        }
    }

    /// @notice Retries the callback to the decryption key receiver with the specified gas limit for a given request ID.
    /// @dev This function allows the owner to retry sending the decryption key to the consumer's
    ///     contract if the original callback failed.
    ///     The function checks if the request has errored, retrieves the necessary request
    ///     and subscription data, and then tries to resend the decryption key.
    /// @param requestID The ID of the request that failed and needs to be retried.
    /// @param newCallbackGasLimit The new gas limit to be used for the retry callback. This should be estimated based on the consumer's contract requirements.
    function retryCallbackWithSubscription(uint256 requestID, uint32 newCallbackGasLimit)
        external
        nonReentrant
        onlyOwner
    {
        require(hasErrored(requestID), "No request with specified requestID");
        TypesLib.DecryptionRequest memory request = requests[requestID];

        TypesLib.BlocklockRequest memory blocklockRequest = IBlocklockSender(request.callback).getRequest(requestID);
        require(blocklockRequest.subId > 0, "Invalid subscription id");

        bytes memory response = abi.encodeWithSelector(
            IDecryptionReceiver.receiveDecryptionData.selector, requestID, request.decryptionKey, request.signature
        );

        bool success = _callWithExactGas(newCallbackGasLimit, request.callback, response);

        if (!success) {
            emit DecryptionReceiverCallbackFailed(requestID);
        } else {
            erroredRequestIds.remove(requestID);
            fulfilledRequestIds.add(requestID);
            emit DecryptionReceiverCallbackSuccess(requestID, request.decryptionKey, request.signature);
        }
    }

    /**
     * @dev See {IDecryptionSender-setSignatureSchemeAddressProvider}.
     */
    function setSignatureSchemeAddressProvider(address newSignatureSchemeAddressProvider) external onlyOwner {
        signatureSchemeAddressProvider = ISignatureSchemeAddressProvider(newSignatureSchemeAddressProvider);
        emit SignatureSchemeAddressProviderUpdated(newSignatureSchemeAddressProvider);
    }

    /**
     * @dev See {IDecryptionSender-isInFlight}.
     */
    function isInFlight(uint256 requestID) public view returns (bool) {
        return unfulfilledRequestIds.contains(requestID) || erroredRequestIds.contains(requestID);
    }

    function hasErrored(uint256 requestID) public view returns (bool) {
        return erroredRequestIds.contains(requestID);
    }

    /**
     * @dev See {IDecryptionSender-getRequest}.
     */
    function getRequest(uint256 requestID) external view returns (TypesLib.DecryptionRequest memory) {
        return requests[requestID];
    }

    function getAllFulfilledRequestIds() external view returns (uint256[] memory) {
        return fulfilledRequestIds.values();
    }

    function getAllUnfulfilledRequestIds() external view returns (uint256[] memory) {
        return unfulfilledRequestIds.values();
    }

    function getAllErroredRequestIds() external view returns (uint256[] memory) {
        return erroredRequestIds.values();
    }

    function getCountOfUnfulfilledRequestIds() external view returns (uint256) {
        return unfulfilledRequestIds.length();
    }

    /**
     * @dev Returns the version number of the upgradeable contract.
     */
    function version() external pure returns (string memory) {
        return "0.0.1";
    }
}
