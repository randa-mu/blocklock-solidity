// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "../libraries/TypesLib.sol";

interface IBlocklockSender {
    /**
     * @notice Requests the generation of a blocklock decryption key at a specific blockHeight.
     * @dev Initiates a blocklock decryption key request.
     * The blocklock decryption key will be generated once the chain reaches the specified `blockHeight`.
     * @return requestID The unique identifier assigned to this blocklock request.
     */
    function requestBlocklock(uint256 blockHeight, TypesLib.Ciphertext calldata ciphertext)
        external
        returns (uint256 requestID);

    /**
     * @notice Updates the decryptionn sender contract address
     * @param newDecryptionSender The decryption sender address to set
     */
    function setDecryptionSender(address newDecryptionSender) external;

    /**
     * @notice Retrieves a specific request by its ID.
     * @dev This function returns the Request struct associated with the given requestId.
     * @param requestId The ID of the request to retrieve.
     * @return The Request struct corresponding to the given requestId.
     */
    function getRequest(uint256 requestId) external view returns (TypesLib.BlocklockRequest memory);

    /**
     * Decrypt a ciphertext into a plaintext using a decryption key.
     * @param ciphertext The ciphertext to decrypt.
     * @param decryptionKey The decryption key that can be used to decrypt the ciphertext.
     */
    function decrypt(TypesLib.Ciphertext calldata ciphertext, bytes calldata decryptionKey)
        external
        view
        returns (bytes memory);

    function version() external pure returns (string memory);
}
