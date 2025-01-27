// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IBlocklockReceiver {
    /**
     * @notice Receives a blocklock decryption key associated with a specific request.
     * @dev This function is called to provide the blocklock decryption generated for a
     * given request ID.
     * It is intended to be called by a trusted source that provides the decryption key.
     * @param requestID The unique identifier of the blocklock request.
     * @param decryptionKey The generated random value, provided as a `bytes` type.
     */
    function receiveBlocklock(uint256 requestID, bytes calldata decryptionKey) external;
}
