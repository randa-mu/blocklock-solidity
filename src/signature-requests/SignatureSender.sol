// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {BLS} from "../libraries/BLS.sol";
import {TypesLib} from "../libraries/TypesLib.sol";
import {BytesLib} from "../libraries/BytesLib.sol";

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";

import {ISignatureReceiver} from "../interfaces/ISignatureReceiver.sol";
import {ISignatureSender} from "../interfaces/ISignatureSender.sol";
import {ISignatureScheme} from "../interfaces/ISignatureScheme.sol";
import {ISignatureSchemeAddressProvider} from "../interfaces/ISignatureSchemeAddressProvider.sol";

/// @notice Smart Contract for Conditional Threshold Signing of messages sent within signature requests.
/// by contract addresses implementing the SignatureReceiverBase abstract contract which implements the ISignatureReceiver interface.
/// @notice Signature requests can also be made for requests requiring immediate signing of messages as the conditions are optional.
contract SignatureSender is ISignatureSender, AccessControl, Multicall {
    using BytesLib for bytes;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    uint256 public lastRequestID = 0;
    BLS.PointG2 private publicKey = BLS.PointG2({x: [uint256(0), uint256(0)], y: [uint256(0), uint256(0)]});
    mapping(uint256 => TypesLib.SignatureRequest) public requestsInFlight;

    ISignatureSchemeAddressProvider public immutable signatureSchemeAddressProvider;

    event SignatureRequested(
        uint256 indexed requestID,
        address indexed callback,
        string schemeID,
        bytes message,
        bytes messageHashToSign,
        bytes condition,
        uint256 requestedAt
    );
    event SignatureRequestFulfilled(uint256 indexed requestID);

    error SignatureCallbackFailed(uint256 requestID);

    modifier onlyOwner() {
        _checkRole(ADMIN_ROLE);
        _;
    }

    constructor(uint256[2] memory x, uint256[2] memory y, address owner, address _signatureSchemeAddressProvider) {
        publicKey = BLS.PointG2({x: x, y: y});
        require(_grantRole(ADMIN_ROLE, owner), "Grant role failed");
        require(_grantRole(DEFAULT_ADMIN_ROLE, owner), "Grant role reverts");
        require(
            _signatureSchemeAddressProvider != address(0),
            "Cannot set zero address as signature scheme address provider"
        );
        signatureSchemeAddressProvider = ISignatureSchemeAddressProvider(_signatureSchemeAddressProvider);
    }

    /**
     * @dev See {ISignatureSender-requestSignature}.
     */
    function requestSignature(string calldata schemeID, bytes calldata message, bytes calldata condition)
        external
        returns (uint256)
    {
        lastRequestID += 1;

        require(signatureSchemeAddressProvider.isSupportedScheme(schemeID), "Signature scheme not supported");
        require(message.isLengthWithinBounds(1, 4096), "Message failed length bounds check");
        // condition is optional
        require(condition.isLengthWithinBounds(0, 4096), "Condition failed length bounds check");
        uint256 conditionLength = condition.length;
        if (conditionLength > 0) {
            require(!condition.isAllZero(), "Condition bytes cannot be all zeros");
        }

        address schemeContractAddress = signatureSchemeAddressProvider.getSignatureSchemeAddress(schemeID);
        ISignatureScheme sigScheme = ISignatureScheme(schemeContractAddress);
        bytes memory messageHash = sigScheme.hashToBytes(message);

        requestsInFlight[lastRequestID] = TypesLib.SignatureRequest({
            callback: msg.sender,
            message: message,
            messageHash: messageHash,
            condition: condition,
            schemeID: schemeID
        });

        emit SignatureRequested(lastRequestID, msg.sender, schemeID, message, messageHash, condition, block.timestamp);
        return lastRequestID;
    }

    /**
     * @dev See {ISignatureSender-fulfilSignatureRequest}.
     */
    function fulfilSignatureRequest(uint256 requestID, bytes calldata signature) external onlyOwner {
        require(isInFlight(requestID), "No request with specified requestID");
        TypesLib.SignatureRequest memory request = requestsInFlight[requestID];

        string memory schemeID = request.schemeID;

        address schemeContractAddress = signatureSchemeAddressProvider.getSignatureSchemeAddress(schemeID);
        ISignatureScheme sigScheme = ISignatureScheme(schemeContractAddress);

        require(
            sigScheme.verifySignature(request.messageHash, signature, getPublicKeyBytes()),
            "Signature verification failed"
        );

        (bool success,) = request.callback.call(
            abi.encodeWithSelector(ISignatureReceiver.receiveSignature.selector, requestID, signature)
        );
        if (!success) {
            revert SignatureCallbackFailed(requestID);
        } else {
            emit SignatureRequestFulfilled(requestID);
            delete requestsInFlight[requestID];
        }
    }

    /**
     * @dev See {ISignatureSender-getPublicKey}.
     */
    function getPublicKey() public view returns (uint256[2] memory, uint256[2] memory) {
        return (publicKey.x, publicKey.y);
    }

    /**
     * @dev See {ISignatureSender-getPublicKeyBytes}.
     */
    function getPublicKeyBytes() public view returns (bytes memory) {
        return BLS.g2Marshal(publicKey);
    }

    /**
     * @dev See {ISignatureSender-isInFlight}.
     */
    function isInFlight(uint256 requestID) public view returns (bool) {
        return requestsInFlight[requestID].callback != address(0);
    }

    /**
     * @dev See {ISignatureSender-getRequestInFlight}.
     */
    function getRequestInFlight(uint256 requestID) external view returns (TypesLib.SignatureRequest memory) {
        return requestsInFlight[requestID];
    }
}
