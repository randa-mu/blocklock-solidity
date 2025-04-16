// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

/// @title IOwnable interface
/// @notice Adapted from Chainlink. Source code available at: https://github.com/smartcontractkit/chainlink/blob/develop/contracts/src/v0.8/shared/interfaces/IOwnable.sol
/// @notice License: MIT
interface IOwnable {
    function owner() external returns (address);

    function transferOwnership(address recipient) external;

    function acceptOwnership() external;
}
