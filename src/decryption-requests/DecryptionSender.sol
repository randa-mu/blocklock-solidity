// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {AccessControlEnumerableUpgradeable} from
    "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import {ContextUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {ScheduledUpgradeable} from "../scheduled-contract-upgrades/ScheduledUpgradeable.sol";

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {BLS} from "../libraries/BLS.sol";
import {TypesLib} from "../libraries/TypesLib.sol";
import {BytesLib} from "../libraries/BytesLib.sol";

import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

import {IDecryptionSender} from "../interfaces/IDecryptionSender.sol";
import {IDecryptionReceiver} from "../interfaces/IDecryptionReceiver.sol";

import {ISignatureScheme} from "../interfaces/ISignatureScheme.sol";
import {ISignatureSchemeAddressProvider} from "../interfaces/ISignatureSchemeAddressProvider.sol";

/// @title Decryption Sender contract
/// @author Randamu
/// @notice Contract used by offchain oracle to fulfill conditional encryption requests.
/// @notice Passes decryption keys via callbacks to the BlocklockSender contract
/// which handles payments for requests and forwards the decryption key to the users receiver contract.
contract DecryptionSender is
    IDecryptionSender,
    ReentrancyGuard,
    Multicall,
    ScheduledUpgradeable,
    AccessControlEnumerableUpgradeable
{
    using BytesLib for bytes;
    using EnumerableSet for EnumerableSet.UintSet;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    uint256 public lastRequestId = 0;

    /// @dev Mapping from decryption requestId to conditional decryption request
    mapping(uint256 => TypesLib.DecryptionRequest) public requests;

    /// @dev Signature scheme address provider contract
    ISignatureSchemeAddressProvider public signatureSchemeAddressProvider;

    /// @dev Set for storing unique fulfilled request Ids
    EnumerableSet.UintSet private fulfilledrequestIds;

    /// @dev Set for storing unique unfulfilled request Ids
    EnumerableSet.UintSet private unfulfilledrequestIds;

    /// @dev Set for storing unique request Ids with failing callbacks
    /// @dev Callbacks can fail if collection of request fee from
    ///      subscription account fails in `_handlePaymentAndCharge` function call.
    ///      We use `_callWithExactGasEvenIfTargetIsNoContract` function for callback so it works if
    ///      caller does not implement the interface.
    EnumerableSet.UintSet private erroredrequestIds;

    /// @dev Emitted when the signature scheme address provider is updated.
    event SignatureSchemeAddressProviderUpdated(address indexed newSignatureSchemeAddressProvider);

    /// @dev Emitted when a decryption request is made.
    /// @param requestId The unique identifier for the decryption request.
    /// @param callback The address that will receive the decryption callback.
    /// @param schemeID The identifier for the signature scheme used.
    /// @param condition The condition to be met for the decryption.
    /// @param ciphertext The encrypted data that needs decryption.
    /// @param requestedAt The timestamp when the decryption request was made.
    event DecryptionRequested(
        uint256 indexed requestId,
        address indexed callback,
        string schemeID,
        bytes condition,
        bytes ciphertext,
        uint256 requestedAt
    );

    /// @dev Emitted when a decryption receiver callback succeeds.
    /// @param requestId The decryption request ID that was fulfilled.
    /// @param decryptionKey The decryption key provided for the request.
    /// @param signature The signature associated with the decryption.
    event DecryptionReceiverCallbackSuccess(uint256 indexed requestId, bytes decryptionKey, bytes signature);

    /// @dev Emitted when a decryption receiver callback fails.
    /// @param requestId The decryption request ID that failed.
    event DecryptionReceiverCallbackFailed(uint256 indexed requestId);

    /// @notice Ensures that only an account with the ADMIN_ROLE can execute a function.
    modifier onlyAdmin() {
        _checkRole(ADMIN_ROLE);
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the DecryptionSender contract with the given parameters.
    /// @param owner The address of the owner to be granted roles.
    /// @param _signatureSchemeAddressProvider The address of the signature scheme provider contract.
    /// @dev This function also sets the owner and signature scheme address provider.
    function initialize(address owner, address _signatureSchemeAddressProvider, address _contractUpgradeBlsValidator)
        public
        initializer
    {
        __UUPSUpgradeable_init();
        __AccessControlEnumerable_init();
        __ScheduledUpgradeable_init(_contractUpgradeBlsValidator, 2 days);

        require(_grantRole(ADMIN_ROLE, owner), "Grant role failed");
        require(_grantRole(DEFAULT_ADMIN_ROLE, owner), "Grant role failed");
        signatureSchemeAddressProvider = ISignatureSchemeAddressProvider(_signatureSchemeAddressProvider);
    }

    /// @dev Overridden upgrade functions

    /// @dev Overridden msg.sender function to return the correct sender address.
    function _msgSender() internal view override (Context, ContextUpgradeable) returns (address) {
        return msg.sender;
    }

    /// @dev Overridden msg.data function to return the correct data.
    function _msgData() internal pure override (Context, ContextUpgradeable) returns (bytes calldata) {
        return msg.data;
    }

    /// @dev Overridden context suffix length function.
    function _contextSuffixLength() internal pure override (Context, ContextUpgradeable) returns (uint256) {
        return 0;
    }

    /// @notice Registers a new decryption request.
    /// @dev The decryption request is recorded, including the encrypted data (ciphertext), conditions, and scheme ID.
    /// This function can be called by any external party wishing to request decryption.
    /// @param schemeID The signature scheme identifier.
    /// @param ciphertext The encrypted data.
    /// @param condition The condition for decryption represented as bytes.
    /// The decryption key is sent to the requesting callback / contract address
    /// when the condition is met.
    /// @return The unique request ID of the decryption request.
    function registerCiphertext(string calldata schemeID, bytes calldata ciphertext, bytes calldata condition)
        external
        returns (uint256)
    {
        lastRequestId += 1;

        require(signatureSchemeAddressProvider.isSupportedScheme(schemeID), "Signature scheme not supported");
        require(ciphertext.isLengthWithinBounds(1, 4096), "Ciphertext failed length bounds check");
        require(condition.isLengthWithinBounds(1, 4096), "Condition failed length bounds check");
        require(!condition.isAllZero(), "Condition bytes cannot be all zeros");

        address schemeContractAddress = signatureSchemeAddressProvider.getSignatureSchemeAddress(schemeID);
        require(schemeContractAddress > address(0), "invalid signature scheme");

        requests[lastRequestId] = TypesLib.DecryptionRequest({
            schemeID: schemeID,
            ciphertext: ciphertext,
            condition: condition,
            decryptionKey: hex"",
            signature: hex"",
            callback: msg.sender,
            isFulfilled: false
        });
        unfulfilledrequestIds.add(lastRequestId);

        emit DecryptionRequested(lastRequestId, msg.sender, schemeID, condition, ciphertext, block.timestamp);

        return lastRequestId;
    }

    /// @notice Fulfills a decryption request by providing the decryption key and signature.
    /// @dev This function validates the provided signature, then sends the decryption key and signature back to the callback address.
    /// @param requestId The unique request ID of the decryption request.
    /// @param decryptionKey The decryption key to fulfill the request.
    /// @param signature The signature corresponding to the decryption.
    function fulfillDecryptionRequest(uint256 requestId, bytes calldata decryptionKey, bytes calldata signature)
        external
        nonReentrant
    {
        require(isInFlight(requestId), "No pending request with specified requestId");
        TypesLib.DecryptionRequest memory request = requests[requestId];

        string memory schemeID = request.schemeID;
        address schemeContractAddress = signatureSchemeAddressProvider.getSignatureSchemeAddress(schemeID);
        require(schemeContractAddress > address(0), "invalid scheme");

        ISignatureScheme sigScheme = ISignatureScheme(schemeContractAddress);
        bytes memory messageHash = sigScheme.hashToBytes(request.condition);

        require(
            sigScheme.verifySignature(messageHash, signature, sigScheme.getPublicKeyBytes()),
            "Signature verification failed"
        );

        (bool success,) = request.callback.call(
            abi.encodeWithSelector(
                IDecryptionReceiver.receiveDecryptionData.selector, requestId, decryptionKey, signature
            )
        );

        requests[requestId].isFulfilled = true;
        unfulfilledrequestIds.remove(requestId);
        if (!success) {
            erroredrequestIds.add(requestId);
            emit DecryptionReceiverCallbackFailed(requestId);
        } else {
            if (hasErrored(requestId)) {
                erroredrequestIds.remove(requestId);
            }
            fulfilledrequestIds.add(requestId);
            emit DecryptionReceiverCallbackSuccess(requestId, decryptionKey, signature);
        }
    }

    /// @notice Sets a new signature scheme address provider.
    /// @dev This allows the contract owner to update the provider used for signature scheme management.
    /// @param newSignatureSchemeAddressProvider The address of the new signature scheme address provider.
    function setSignatureSchemeAddressProvider(address newSignatureSchemeAddressProvider) external onlyAdmin {
        signatureSchemeAddressProvider = ISignatureSchemeAddressProvider(newSignatureSchemeAddressProvider);
        emit SignatureSchemeAddressProviderUpdated(newSignatureSchemeAddressProvider);
    }

    /// @notice Checks if a decryption request is still in progress (unfulfilled or errored).
    /// @dev Used to check if a request is either still awaiting decryption or has encountered an error.
    /// @param requestId The unique request ID of the decryption request.
    /// @return True if the request is in flight (unfulfilled or errored), false otherwise.
    function isInFlight(uint256 requestId) public view returns (bool) {
        return unfulfilledrequestIds.contains(requestId) || erroredrequestIds.contains(requestId);
    }

    /// @notice Checks if a decryption request has errored out.
    /// @dev Used to check if the request has failed and is in the errored state.
    /// @param requestId The unique request ID of the decryption request.
    /// @return True if the request has errored, false otherwise.
    function hasErrored(uint256 requestId) public view returns (bool) {
        return erroredrequestIds.contains(requestId);
    }

    /// @notice Retrieves the details of a decryption request.
    /// @dev Returns the full decryption request data for the given request ID.
    /// @param requestId The unique request ID.
    /// @return The decryption request object.
    function getRequest(uint256 requestId) external view returns (TypesLib.DecryptionRequest memory) {
        return requests[requestId];
    }

    /// @notice Retrieves all fulfilled request IDs.
    /// @dev Returns an array of all fulfilled request IDs.
    /// @return An array of fulfilled request IDs.
    function getAllFulfilledRequestIds() external view returns (uint256[] memory) {
        return fulfilledrequestIds.values();
    }

    /// @notice Retrieves all unfulfilled request IDs.
    /// @dev Returns an array of all unfulfilled request IDs.
    /// @return An array of unfulfilled request IDs.
    function getAllUnfulfilledRequestIds() external view returns (uint256[] memory) {
        return unfulfilledrequestIds.values();
    }

    /// @notice Retrieves all errored request IDs.
    /// @dev Returns an array of all errored request IDs.
    /// @return An array of errored request IDs.
    function getAllErroredRequestIds() external view returns (uint256[] memory) {
        return erroredrequestIds.values();
    }

    /// @notice Retrieves the count of unfulfilled request IDs.
    /// @dev Returns the number of unfulfilled decryption requests.
    /// @return The number of unfulfilled request IDs.
    function getCountOfUnfulfilledRequestIds() external view returns (uint256) {
        return unfulfilledrequestIds.length();
    }

    /// @notice Returns the version number of the upgradeable contract.
    /// @dev This allows querying of the current contract version.
    /// @return The version number as a string.
    function version() external pure returns (string memory) {
        return "0.0.1";
    }
}
