// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {IOwnable} from "../interfaces/IOwnable.sol";

/// @title ConfirmedOwnerWithProposal contract
/// @notice A contract with helpers for basic contract ownership.
/// @notice Adopted from Chainlink. Source code available at: https://github.com/smartcontractkit/chainlink/blob/develop/contracts/src/v0.8/shared/access/ConfirmedOwnerWithProposal.sol
/// @notice License: MIT
contract ConfirmedOwnerWithProposal is IOwnable {
    address private s_owner;
    address private s_pendingOwner;

    event OwnershipTransferRequested(address indexed from, address indexed to);
    event OwnershipTransferred(address indexed from, address indexed to);

    constructor(address newOwner, address pendingOwner) {
        require(newOwner != address(0), "Cannot set owner to zero");

        s_owner = newOwner;
        if (pendingOwner != address(0)) {
            _transferOwnership(pendingOwner);
        }
    }

    /// @notice Allows an owner to begin transferring ownership to a new address.
    function transferOwnership(address to) public override onlyOwner {
        _transferOwnership(to);
    }

    /// @notice Allows an ownership transfer to be completed by the recipient.
    function acceptOwnership() external override {
        require(msg.sender == s_pendingOwner, "Must be proposed owner");

        address oldOwner = s_owner;
        s_owner = msg.sender;
        s_pendingOwner = address(0);

        emit OwnershipTransferred(oldOwner, msg.sender);
    }

    /// @notice Get the current owner
    function owner() public view override returns (address) {
        return s_owner;
    }

    /// @notice validate, transfer ownership, and emit relevant events
    function _transferOwnership(address to) private {
        // solhint-disable-next-line gas-custom-errors
        require(to != msg.sender, "Cannot transfer to self");

        s_pendingOwner = to;

        emit OwnershipTransferRequested(s_owner, to);
    }

    /// @notice validate access
    function _validateOwnership() internal view {
        // solhint-disable-next-line gas-custom-errors
        require(msg.sender == s_owner, "Only callable by owner");
    }

    /// @notice Reverts if called by anyone other than the contract owner.
    modifier onlyOwner() {
        _validateOwnership();
        _;
    }
}
