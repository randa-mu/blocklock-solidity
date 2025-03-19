// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {BLS} from "../libraries/BLS.sol";
import {ISignatureScheme} from "../interfaces/ISignatureScheme.sol";

contract BlocklockSignatureScheme is ISignatureScheme {
    using BLS for bytes;

    string public constant SCHEME_ID = "BN254-BLS-BLOCKLOCK";
    bytes public constant DST = bytes("BLOCKLOCK_BN254G1_XMD:KECCAK-256_SVDW_RO_H1_");

    /**
     * @dev See {ISignatureScheme-verifySignature}.
     */
    function verifySignature(bytes calldata message, bytes calldata signature, bytes calldata publicKey)
        external
        view
        returns (bool isValid)
    {
        // convert message hash bytes to g1
        BLS.PointG1 memory _message = BLS.g1Unmarshal(message);
        // convert signature bytes to g1
        BLS.PointG1 memory _signature = BLS.g1Unmarshal(signature);
        // convert public key bytes to g2
        BLS.PointG2 memory _publicKey = BLS.g2Unmarshal(publicKey);
        // call evm precompile for pairing check
        (bool pairingSuccess, bool callSuccess) = BLS.verifySingle(_signature, _publicKey, _message);
        return (pairingSuccess && callSuccess);
    }

    /**
     * @dev See {ISignatureScheme-hashToPoint}.
     */
    function hashToPoint(bytes calldata message) public view returns (uint256, uint256) {
        BLS.PointG1 memory point = BLS.hashToPoint(DST, message);
        return (point.x, point.y);
    }

    /**
     * @dev See {ISignatureScheme-hashToBytes}.
     */
    function hashToBytes(bytes calldata message) external view returns (bytes memory) {
        (uint256 x, uint256 y) = hashToPoint(message);
        return BLS.g1Marshal(BLS.PointG1({x: x, y: y}));
    }
}
