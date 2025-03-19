// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ISignatureSchemeAddressProvider} from "../interfaces/ISignatureSchemeAddressProvider.sol";

contract SignatureSchemeAddressProvider is ISignatureSchemeAddressProvider, AccessControl {
    mapping(string => address) private schemes;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    event NewSignatureSchemeAddressAdded(string indexed schemeID, address indexed schemeAddress, uint256 addedAt);

    modifier onlyOwner() {
        _checkRole(ADMIN_ROLE);
        _;
    }

    constructor(address owner) {
        if (owner == address(0)) {
            owner = msg.sender;
        }
        require(_grantRole(DEFAULT_ADMIN_ROLE, owner), "Grant role failed");
        require(_grantRole(ADMIN_ROLE, owner), "Grant role failed");
    }

    /**
     * @dev See {ISignatureSchemeAddressProvider-updateSignatureScheme}.
     */
    function updateSignatureScheme(string calldata schemeID, address schemeAddress) external onlyOwner {
        require(
            !(schemeAddress == address(0) && schemeAddress.code.length == 0),
            "Invalid contract address for schemeAddress"
        );
        schemes[schemeID] = schemeAddress;
        emit NewSignatureSchemeAddressAdded(schemeID, schemes[schemeID], block.timestamp);
    }

    /**
     * @dev See {ISignatureSchemeAddressProvider-getSignatureSchemeAddress}.
     */
    function getSignatureSchemeAddress(string calldata schemeID) external view returns (address) {
        return schemes[schemeID];
    }

    /**
     * @dev See {ISignatureSchemeAddressProvider-isSupportedScheme}.
     */
    function isSupportedScheme(string calldata schemeID) external view returns (bool) {
        return schemes[schemeID] != address(0);
    }
}
