// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ISignatureSchemeAddressProvider} from "../interfaces/ISignatureSchemeAddressProvider.sol";

/// @title SignatureSchemeAddressProvider contract
/// @notice Manages and provides addresses of signature scheme contracts using their unique scheme identifier string.
/// @dev Uses OpenZeppelin's AccessControl for role-based access management.
contract SignatureSchemeAddressProvider is ISignatureSchemeAddressProvider, AccessControl {
    /// @notice Mapping of signature scheme identifiers to their corresponding contract addresses.
    mapping(string => address) private schemes;

    /// @notice Role identifier for administrators who can update the signature schemes.
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /// @notice Emitted when a new signature scheme address is added.
    /// @param schemeID The identifier of the signature scheme.
    /// @param schemeAddress The address of the signature scheme contract.
    /// @param addedAt The timestamp when the scheme was added.
    event NewSignatureSchemeAddressAdded(string indexed schemeID, address indexed schemeAddress, uint256 addedAt);

    /// @notice Ensures that only an account with the ADMIN_ROLE can execute a function.
    modifier onlyAdmin() {
        _checkRole(ADMIN_ROLE);
        _;
    }

    /// @notice Initializes the contract and assigns the deployer or provided owner as the administrator.
    /// @dev Grants the `DEFAULT_ADMIN_ROLE` and `ADMIN_ROLE` to the specified owner.
    /// @param owner The address that will be assigned as the administrator. Defaults to the deployer if zero address is provided.
    constructor(address owner) {
        if (owner == address(0)) {
            owner = msg.sender;
        }
        require(_grantRole(DEFAULT_ADMIN_ROLE, owner), "Grant role failed");
        require(_grantRole(ADMIN_ROLE, owner), "Grant role failed");
    }

    /// @notice Updates the contract address of a given signature scheme.
    /// @dev Ensures the provided contract address is non-zero and contains contract code.
    /// @param schemeID The identifier of the signature scheme.
    /// @param schemeAddress The new address of the signature scheme contract.
    function updateSignatureScheme(string calldata schemeID, address schemeAddress) external onlyAdmin {
        require(
            (schemeAddress != address(0) && schemeAddress.code.length != 0),
            "Invalid contract address for schemeAddress"
        );
        schemes[schemeID] = schemeAddress;
        emit NewSignatureSchemeAddressAdded(schemeID, schemes[schemeID], block.timestamp);
    }

    /// @notice Retrieves the contract address of a given signature scheme.
    /// @param schemeID The identifier of the signature scheme.
    /// @return The address of the corresponding signature scheme contract.
    function getSignatureSchemeAddress(string calldata schemeID) external view returns (address) {
        return schemes[schemeID];
    }

    /// @notice Checks whether a given signature scheme is supported.
    /// @param schemeID The identifier of the signature scheme.
    /// @return True if the scheme exists, otherwise false.
    function isSupportedScheme(string calldata schemeID) external view returns (bool) {
        return schemes[schemeID] != address(0);
    }
}
