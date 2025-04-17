// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {ConfirmedOwnerWithProposal} from "./ConfirmedOwnerWithProposal.sol";

/// @title ConfirmedOwner contract
/// @notice A contract with helpers for basic contract ownership.
/// @notice Adopted from Chainlink. Source code available at: https://github.com/smartcontractkit/chainlink/blob/develop/contracts/src/v0.8/shared/access/ConfirmedOwner.sol
/// @notice License: MIT
contract ConfirmedOwner is ConfirmedOwnerWithProposal {
    constructor(address newOwner) ConfirmedOwnerWithProposal(newOwner, address(0)) {}
}
