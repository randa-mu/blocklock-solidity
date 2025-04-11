// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

/// @title ISignatureSchemeAddressProvider interface
/// @author Randamu
/// @notice Enables the support for multiple signature schemes, e.g., BN254, BLS, etc.
/// in a single contract.
interface ISignatureSchemeAddressProvider {
    /// @notice Adds support for a new signature scheme to the registry.
    /// @notice Only contract admin or governance can add.
    /// @param schemeID The name of the signature scheme (e.g., BN254, BLS12-381, TESS)
    /// @param schemeAddress The contract address implementing the signature verification scheme
    function updateSignatureScheme(string calldata schemeID, address schemeAddress) external;

    /// @notice Retrieves the contract address associated with a specific signature scheme.
    /// @dev Looks up the address of the signature scheme contract identified by `schemeID`.
    /// @param schemeID The identifier of the signature scheme to look up.
    /// @return The contract address associated with the specified signature scheme.
    function getSignatureSchemeAddress(string calldata schemeID) external view returns (address);

    /// @notice Checks if a specified signature scheme is supported.
    /// @dev Determines whether the signature scheme identified by `schemeID` is currently supported.
    /// @param schemeID The identifier of the signature scheme to check.
    /// @return True if the signature scheme is supported, otherwise false.
    function isSupportedScheme(string calldata schemeID) external view returns (bool);
}
