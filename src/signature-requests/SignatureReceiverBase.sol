// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ISignatureReceiver} from "../interfaces/ISignatureReceiver.sol";
import {ISignatureSender} from "../interfaces/ISignatureSender.sol";

abstract contract SignatureReceiverBase is ISignatureReceiver {
    ISignatureSender internal immutable signatureSender;

    modifier onlySignatureSender() {
        require(msg.sender == address(signatureSender), "Only signatureSender can call");
        _;
    }

    constructor(address _signatureSender) {
        require(_signatureSender != address(0), "Cannot set zero address as signature sender");
        signatureSender = ISignatureSender(_signatureSender);
    }

    /**
     * @notice Initiates a signature request for a given message under a specified signature scheme.
     * @dev This internal function calls the `requestSignature` function of the `signatureSender` contract.
     * It passes the provided `schemeID`, `message`, and `condition` to the signature sender.
     * @param schemeID The identifier of the signature scheme to be used for signing the message.
     * @param message The message to be signed, provided as a byte array.
     * @param condition Additional conditions that must be satisfied for the signature request, provided as a byte array.
     * @return requestID The unique identifier assigned to the initiated signature request.
     */
    function requestSignature(string calldata schemeID, bytes calldata message, bytes calldata condition)
        internal
        returns (uint256)
    {
        return signatureSender.requestSignature(schemeID, message, condition);
    }

    /**
     * @dev See {ISignatureReceiver-receiveSignature}.
     */
    function receiveSignature(uint256 requestID, bytes calldata signature) external onlySignatureSender {
        onSignatureReceived(requestID, signature);
    }

    /**
     * @notice Handles the reception of a digital signature for a specified request.
     * @dev This internal function is called when a signature is received for the given `requestID`.
     * It is intended to be overridden by derived contracts to implement custom behavior upon receipt of a signature.
     * @param requestID The unique identifier of the signature request associated with the received signature.
     * @param signature The cryptographic signature of the message, provided as a byte array.
     */
    function onSignatureReceived(uint256 requestID, bytes calldata signature) internal virtual;
}
