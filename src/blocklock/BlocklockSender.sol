// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

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

import {console} from "forge-std/console.sol";

contract BlocklockSender is
    IBlocklockSender,
    DecryptionReceiverBase,
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

    // Mapping from decryption requestID to blocklock status
    mapping(uint256 => TypesLib.BlocklockRequest) public blocklockRequests;

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
        returns (uint256)
    {
        require(blockHeight > block.number, "blockHeight must be strictly greater than current");

        TypesLib.BlocklockRequest memory r = TypesLib.BlocklockRequest({
            decryptionRequestID: 0,
            blockHeight: blockHeight,
            ciphertext: ciphertext,
            signature: hex"",
            callback: msg.sender
        });

        // New decryption request
        bytes memory conditions = abi.encode(blockHeight);

        uint256 decryptionRequestID = decryptionSender.registerCiphertext(SCHEME_ID, abi.encode(ciphertext), conditions);
        r.decryptionRequestID = decryptionRequestID;

        // Store the signature requestID for this blockHeight
        blocklockRequests[decryptionRequestID] = r;

        emit BlocklockRequested(decryptionRequestID, blockHeight, ciphertext, msg.sender, block.timestamp);
        return decryptionRequestID;
    }

    /**
     * @dev See {DecryptionReceiverBase-onDecryptionDataReceived}.
     */
    function onDecryptionDataReceived(uint256 decryptionRequestID, bytes memory decryptionKey, bytes memory signature)
        internal
        override
    {
        TypesLib.BlocklockRequest memory r = blocklockRequests[decryptionRequestID];
        require(r.decryptionRequestID > 0, "no matching blocklock request for that id");

        r.signature = signature;

        (bool success,) = r.callback.call(
            abi.encodeWithSelector(IBlocklockReceiver.receiveBlocklock.selector, decryptionRequestID, decryptionKey)
        );

        if (!success) {
            revert BlocklockCallbackFailed(decryptionRequestID);
        } else {
            emit BlocklockCallbackSuccess(decryptionRequestID, r.blockHeight, r.ciphertext, decryptionKey);
            delete blocklockRequests[decryptionRequestID];
        }
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

    /**
     * @dev See {ISignatureSender-isInFlight}.
     */
    function isInFlight(uint256 requestID) external view returns (bool) {
        uint256 signatureRequestID = blocklockRequests[requestID].decryptionRequestID;
        require(signatureRequestID > 0, "blocklock request not found");

        return decryptionSender.isInFlight(signatureRequestID);
    }

    /**
     * @dev See {IBlocklockSender-getRequest}.
     */
    function getRequest(uint256 requestID) external view returns (TypesLib.BlocklockRequest memory) {
        TypesLib.BlocklockRequest memory r = blocklockRequests[requestID];
        require(r.decryptionRequestID > 0, "invalid requestID");

        return r;
    }

    /**
     * @dev Returns the version number of the upgradeable contract.
     */
    function version() external pure returns (string memory) {
        return "1.0.0";
    }
}
